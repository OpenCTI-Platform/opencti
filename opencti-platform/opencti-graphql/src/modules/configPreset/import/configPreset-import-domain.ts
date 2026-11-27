import crypto from 'node:crypto';
import { logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { downloadFile } from '../../../database/raw-file-storage';
import { deleteFile, type FileUploadData, loadFile, type LoadedFile, uploadToStorage } from '../../../database/file-storage';
import type { AuthContext, AuthUser } from '../../../types/user';
import type {
  ConfigPresetImportExpected,
  ConfigPresetImportItemConnection,
  ConfigPresetImportPreview,
  ConfigPresetImportType,
  QueryConfigPresetImportItemsArgs,
} from '../../../generated/graphql';
import type { ConfigImportMode } from '../../configImport/configImport-types';
import { allFilesForPaths } from '../../internal/document/document-domain';
import { CONFIG_PRESET_HISTORY_PATH, CONFIG_PRESET_IMPORT_PATH } from '../../internal/document/document-types';
import type { ConfigPresetFamilyDefinition } from '../configPreset-types';
import { CONFIG_PRESET_FAMILIES, configPresetFamilyType, isConfigPresetFamilyAvailable } from '../configPreset-registry';
import { CONFIG_PRESET_FIRST_PAGE_SIZE } from '../export/configPreset-export-domain';
import {
  checkConfigPresetImportAccess,
  CONFIG_PRESET_RESULT_STATUSES,
  configPresetImportMode,
  getConfigPresetFamilyModes,
  getConfigPresetPlatformId,
  detachConfigPresetImportContext,
  throwIfConfigPresetRequestAborted,
} from './configPreset-import-utils';
import { applyConfigPresetImportEvent, checkConfigPresetImportNotApplying } from './configPreset-import-session-domain';
import { dropConfigPresetImportCache, getConfigPresetImportIndex, getConfigPresetImportSnapshot, setConfigPresetImportIndex } from './configPreset-import-cache';
import {
  CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE,
  type ConfigPresetItemKey,
  limitStream,
  readConfigPresetBundle,
  createConfigPresetBundleSnapshot,
  restoreConfigPresetBundle,
  readStreamWithLimit,
  resolveBundleDependencies,
} from './configPreset-import-bundle';
import {
  CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED,
  CONFIG_PRESET_REASON_FILE_MISSING,
  type ConfigPresetBundle,
  type ConfigPresetBundleItem,
  type ConfigPresetComputedItem,
  type ConfigPresetImportCredentials,
  type ConfigPresetImportIndex,
  type ConfigPresetImportPlan,
} from './configPreset-import-types';

const fileMissing = () => FunctionalError('The uploaded file no longer exists', { reason: CONFIG_PRESET_REASON_FILE_MISSING });

// One pending upload per user: the previous ones are deleted, a failed deletion never fails the upload
const deleteOtherUploads = async (context: AuthContext, user: AuthUser, keepId: string) => {
  try {
    const files = await allFilesForPaths(context, user, [CONFIG_PRESET_IMPORT_PATH], { creator_id: user.id });
    for (let i = 0; i < files.length; i += 1) {
      if (files[i].id !== keepId) {
        try {
          await deleteFile(context, user, files[i].id, { forceDelete: true });
        } catch (err) {
          logApp.warn('[CONFIG PRESET] Failed to delete a previous import upload', { cause: err, file_id: files[i].id });
        }
      }
    }
  } catch (err) {
    logApp.warn('[CONFIG PRESET] Failed to list the previous import uploads', { cause: err });
  }
};

// An upload that was never imported is not kept: a wizard session is a matter of minutes. The history (the report and the zip it
// was made from) is what an administrator may want to download again, so it is kept longer.
export const CONFIG_PRESET_IMPORT_UPLOAD_RETENTION_MS = 24 * 60 * 60 * 1000;
export const CONFIG_PRESET_IMPORT_HISTORY_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

const deleteExpiredFiles = async (context: AuthContext, user: AuthUser, path: string, retentionMs: number) => {
  try {
    const notModifiedSince = new Date(Date.now() - retentionMs).toISOString();
    const expiredFiles = await allFilesForPaths(context, user, [path], { notModifiedSince });
    for (let i = 0; i < expiredFiles.length; i += 1) {
      try {
        await deleteFile(context, user, expiredFiles[i].id, { forceDelete: true });
      } catch (err) {
        logApp.warn('[CONFIG PRESET] Failed to delete an expired import file', { cause: err, file_id: expiredFiles[i].id });
      }
    }
  } catch (err) {
    logApp.warn('[CONFIG PRESET] Failed to delete the expired import files', { cause: err, path });
  }
};

// Called by the garbage collection manager. A failed deletion does not stop the others: the next run retries it.
// A session whose pending zip is gone reads it as a missing file and goes back to the upload.
export const deleteExpiredConfigPresetImportFiles = async (context: AuthContext, user: AuthUser) => {
  await deleteExpiredFiles(context, user, CONFIG_PRESET_IMPORT_PATH, CONFIG_PRESET_IMPORT_UPLOAD_RETENTION_MS);
  await deleteExpiredFiles(context, user, CONFIG_PRESET_HISTORY_PATH, CONFIG_PRESET_IMPORT_HISTORY_RETENTION_MS);
};

export const configPresetImportUpload = async (context: AuthContext, user: AuthUser, file: Promise<FileUploadData>): Promise<LoadedFile> => {
  checkConfigPresetImportAccess(context, user);
  // Refused before anything is stored: the deletion of the previous uploads would delete the zip being imported
  await checkConfigPresetImportNotApplying(context, user);
  const { createReadStream, filename } = await file;
  const { upload } = await uploadToStorage(
    context,
    user,
    `${CONFIG_PRESET_IMPORT_PATH}/${crypto.randomUUID()}`,
    { createReadStream: () => limitStream(createReadStream(), CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE), filename },
    { noTriggerImport: true, meta: { description: 'Configuration preset import' } },
  );
  try {
    await applyConfigPresetImportEvent(context, user, 'UPLOAD', { platform_id: await getConfigPresetPlatformId(context), file_id: upload.id });
  } catch (err) {
    await deleteFile(context, user, upload.id, { forceDelete: true }).catch((deleteErr) => logApp.warn('[CONFIG PRESET] Failed to delete a refused upload', { cause: deleteErr }));
    throw err;
  }
  await deleteOtherUploads(context, user, upload.id);
  // What was kept of the previous zip is of no use any more
  dropConfigPresetImportCache(user.id);
  return upload;
};

// The stored zip of the calling user: the path and the creator are checked on the resolved id, as loadFile
// matches case-insensitively and does not check the creator
export const loadConfigPresetImportZip = async (context: AuthContext, user: AuthUser, fileId: string): Promise<Buffer> => {
  const file = await loadFile(context, user, fileId, { dontThrow: true });
  const resolvedId = file?.internal_id ?? file?.id;
  if (!file || !resolvedId?.startsWith(`${CONFIG_PRESET_IMPORT_PATH}/`) || file.metaData.creator_id !== user.id) {
    throw fileMissing();
  }
  const stream = await downloadFile(resolvedId);
  if (!stream) {
    throw fileMissing();
  }
  return readStreamWithLimit(stream, CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE, () => FunctionalError('The configuration bundle is too large', { reason: 'bundle_refused' }));
};

// The bundle of an uploaded zip. The preview and the dry runs read it through the snapshot kept for a few minutes (the zip is not read again),
// the import reads the zip itself (fresh): what it writes is read from the file as it is when it runs, never from what was kept.
// Hit or miss, the bundle comes from the snapshot: both give the same one.
export const readConfigPresetImportBundle = async (
  context: AuthContext,
  user: AuthUser,
  fileId: string,
  { fresh = false }: { fresh?: boolean } = {},
): Promise<ConfigPresetBundle> => {
  checkConfigPresetImportAccess(context, user);
  const openZip = () => loadConfigPresetImportZip(context, user, fileId);
  if (fresh) {
    return readConfigPresetBundle(await openZip());
  }
  // The snapshot is shared by the requests that ask for it while it is read: its read is not the one of the first of them, which can be
  // cancelled (and is, when the dialog closes) while another one waits for it
  const readZip = () => loadConfigPresetImportZip(detachConfigPresetImportContext(context), user, fileId);
  const snapshot = await getConfigPresetImportSnapshot(user.id, fileId, async () => createConfigPresetBundleSnapshot(await readZip()));
  return restoreConfigPresetBundle(snapshot, openZip);
};

// Whether the platform can use each family of the items, by family id. Read once for a computation, so that its items and its types agree
export const getConfigPresetFamiliesAvailability = async (context: AuthContext, items: ConfigPresetBundleItem[]) => {
  const families = CONFIG_PRESET_FAMILIES.filter((family) => items.some((item) => item.type === family.id));
  return new Map(await Promise.all(families.map(async (family) => [family.id, await isConfigPresetFamilyAvailable(context, family)] as const)));
};

// What the importer of the family decides for an item. A family that requires the Enterprise Edition skips its items on a platform
// without it. Without isAvailable the platform is read at each call: the real import computes each item just before it writes it,
// and a license applied since the preview is taken into account.
export const computeConfigPresetItem = async (
  context: AuthContext,
  user: AuthUser,
  family: ConfigPresetFamilyDefinition,
  item: ConfigPresetBundleItem,
  plan: ConfigPresetImportPlan,
  mode: ConfigImportMode,
  isAvailable?: boolean,
): Promise<ConfigPresetComputedItem> => {
  // The importer of a family the platform cannot import is never called: it may read through domain functions that refuse without
  // the Enterprise Edition, and what it would validate or find is of no use. The item is named after its family.
  if (!(isAvailable ?? await isConfigPresetFamilyAvailable(context, family))) {
    return { label: family.label, translatable: true, exists: false, conflict: false, status: 'skipped', reason: CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED };
  }
  return family.importer!.compute(context, user, item, plan, mode);
};

// Lets the importers that have a prepare read, in one query per family, what their items need: only the families the platform can use
// (the importer of another one is never called), and only the ones that have items
export const prepareConfigPresetItems = async (
  context: AuthContext,
  user: AuthUser,
  items: ConfigPresetBundleItem[],
  plan: ConfigPresetImportPlan,
  availability: Map<string, boolean>,
) => {
  const families = CONFIG_PRESET_FAMILIES.filter((family) => family.importer?.prepare && availability.get(family.id));
  for (let i = 0; i < families.length; i += 1) {
    const familyItems = items.filter((item) => item.type === families[i].id);
    if (familyItems.length > 0) {
      await families[i].importer!.prepare!(context, user, familyItems, plan);
    }
  }
};

// The counterpart of prepareConfigPresetItems, at the end of a real import: the importers that have a finalize run it once, for the
// families that had items. Whatever they do (a refresh of an index) never fails the import: it is logged.
export const finalizeConfigPresetItems = async (
  context: AuthContext,
  user: AuthUser,
  items: ConfigPresetBundleItem[],
  plan: ConfigPresetImportPlan,
  availability: Map<string, boolean>,
) => {
  const families = CONFIG_PRESET_FAMILIES.filter((family) => family.importer?.finalize && availability.get(family.id));
  for (let i = 0; i < families.length; i += 1) {
    if (items.some((item) => item.type === families[i].id)) {
      try {
        await families[i].importer!.finalize!(context, user, plan);
      } catch (err) {
        logApp.warn('[CONFIG PRESET] The end of the import of a family failed', { cause: err, family: families[i].id });
      }
    }
  }
};

// compute of every item, required dependencies first: reads only, the plan records what would be created
// modes: the mode of each item, defaultMode for the items that have none (OVERWRITE when absent: the preview, the dependencies)
// availability: the families the platform can use, when the caller has read it already
export const computeConfigPresetItems = async (
  context: AuthContext,
  user: AuthUser,
  items: ConfigPresetBundleItem[],
  { modes = new Map(), availability, defaultMode, credentials = new Map(), serviceAccounts = new Map() }: {
    modes?: Map<string, ConfigImportMode>;
    availability?: Map<string, boolean>;
    defaultMode?: ConfigImportMode;
    credentials?: ConfigPresetImportCredentials;
    serviceAccounts?: Map<string, string>;
  } = {},
): Promise<{ item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[]> => {
  const familiesAvailability = availability ?? await getConfigPresetFamiliesAvailability(context, items);
  const plan: ConfigPresetImportPlan = {
    created: new Set(),
    themeNames: new Set(),
    releasedThemeNames: new Set(),
    emailTemplateNames: new Set(),
    roleIds: new Set(),
    groupIds: new Set(),
    roleSensitiveRights: new Map(),
    plannedMarkings: new Map(),
    targets: new Map(),
    connectorNames: new Set(),
    fintelDesignNames: new Set(),
    renamedFintelDesignIds: new Set(),
    credentials,
    serviceAccounts,
  };
  await prepareConfigPresetItems(context, user, items, plan, familiesAvailability);
  const results: { item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[] = [];
  for (let i = 0; i < items.length; i += 1) {
    throwIfConfigPresetRequestAborted(context);
    const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === items[i].type)!;
    const mode = configPresetImportMode(modes, items[i].type, items[i].id, defaultMode);
    results.push({ item: items[i], computed: await computeConfigPresetItem(context, user, family, items[i], plan, mode, familiesAvailability.get(family.id)) });
  }
  return results;
};

const pageInfoOf = (globalCount: number, hasNextPage = false) => ({ startCursor: '', endCursor: '', hasNextPage, hasPreviousPage: false, globalCount });

// The types of the computed items, in registry order, each with its items: what already exists, the values they would write
// and their required dependencies. A family the platform cannot import is locked, without its items.
// Shared by the preview of the wizard and the one of a partial import: every item is listed, the wizard pages some types afterwards.
export const buildConfigPresetImportTypes = (
  bundle: ConfigPresetBundle,
  results: { item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[],
  availability: Map<string, boolean>,
): ConfigPresetImportType[] => {
  const defaultThemeId = bundle.items.find((item) => item.type === 'platform')?.configuration.default_theme as { standard_id?: string } | null | undefined;
  const families = CONFIG_PRESET_FAMILIES.filter((family) => results.some(({ item }) => item.type === family.id));
  // The position of each item of the bundle by its path, read once: a search of the whole bundle for each item is the square of its size
  const itemIndexByPath = new Map(bundle.items.map((item, index) => [item.path, index]));
  return families.map((family) => {
    // The items of a family the platform cannot import are not shown: the dialog shows the type as locked
    const items = !availability.get(family.id) ? [] : results.filter(({ item }) => item.type === family.id).map(({ item, computed }) => {
      const dependencyPaths = Object.values(bundle.dependencies[configPresetFamilyType(family)]?.[item.id] ?? {});
      return {
        key: item.id,
        label: computed.label,
        translatable: computed.translatable,
        // The default theme is the one the platform item points to; any other default is said by the item itself
        isDefault: computed.isDefault ?? (family.id === 'branding' && defaultThemeId?.standard_id === item.id),
        exists: computed.exists,
        conflict: computed.conflict,
        fields: computed.fields ?? [],
        isEnabled: computed.isEnabled ?? null,
        credentials: computed.credentials ?? [],
        serviceAccountRequired: computed.serviceAccountRequired ?? false,
        // In the order of the bundle, each dependency once; one that is not in the bundle is not listed
        dependsOn: [...new Set(dependencyPaths.flatMap((path) => itemIndexByPath.get(path) ?? []))]
          .sort((a, b) => a - b)
          .map((index) => ({ type: bundle.items[index].type, key: bundle.items[index].id })),
      };
    });
    return {
      key: family.id,
      label: family.label,
      description: family.description,
      group: { key: family.group.id, label: family.group.label },
      lockedByEnterpriseEdition: !availability.get(family.id),
      modes: getConfigPresetFamilyModes(family),
      items,
      itemsPageInfo: pageInfoOf(items.length),
      conflictsCount: items.filter(({ conflict }) => conflict).length,
    };
  });
};

// A type with more items than this is listed page by page, when nothing in it asks the user for anything: a credential, a service account and a
// mode are chosen item by item in the dialog, which needs those items in hand, and such a type has dozens of items, not thousands.
export const CONFIG_PRESET_IMPORT_PAGED_FROM = 200;
// What a paged type lists in the preview: the next pages come from configPresetImportItems
export const CONFIG_PRESET_IMPORT_FIRST_PAGE_SIZE = CONFIG_PRESET_FIRST_PAGE_SIZE;
const CONFIG_PRESET_IMPORT_DEFAULT_PAGE_SIZE = 25;
const CONFIG_PRESET_IMPORT_MAX_PAGE_SIZE = 200;

const isPagedConfigPresetImportType = (type: ConfigPresetImportType) => {
  return !type.lockedByEnterpriseEdition
    && type.items.length > CONFIG_PRESET_IMPORT_PAGED_FROM
    && type.modes.length <= 1
    && type.items.every((item) => item.credentials.length === 0 && !item.serviceAccountRequired);
};

// The preview of a bundle: every type, a paged one with its first page only. The index holds all the items of the paged types.
// Reads the platform for each item of the bundle once: this is what the preview costs.
const computeConfigPresetImportPreviewTypes = async (context: AuthContext, user: AuthUser, bundle: ConfigPresetBundle) => {
  const keys: ConfigPresetItemKey[] = bundle.items;
  const ordered = resolveBundleDependencies(bundle, keys);
  const availability = await getConfigPresetFamiliesAvailability(context, ordered);
  const results = await computeConfigPresetItems(context, user, ordered, { availability });
  const index: ConfigPresetImportIndex = new Map();
  // What the import would do with each item when everything is selected: the rows of a paged type show it, a dry run does not return it
  const expected = new Map(results.map(({ item, computed }) => [`${item.type}/${item.id}`, { status: CONFIG_PRESET_RESULT_STATUSES[computed.status] as ConfigPresetImportExpected['status'], reason: computed.reason ?? null, code: computed.code ?? null }]));
  const types = buildConfigPresetImportTypes(bundle, results, availability).map((type) => {
    if (!isPagedConfigPresetImportType(type)) {
      return type;
    }
    const items = type.items.map((item) => ({ ...item, expected: expected.get(`${type.key}/${item.key}`) ?? null }));
    index.set(type.key, items);
    return { ...type, items: items.slice(0, CONFIG_PRESET_IMPORT_FIRST_PAGE_SIZE), itemsPageInfo: pageInfoOf(items.length, true) };
  });
  return { types, index };
};

// The items of the zip per family, with what already exists, the values they would write and their required dependencies.
// The index of the paged types is kept with the file: the preview is the moment the dialog reads what the platform holds.
export const configPresetImportPreview = async (context: AuthContext, user: AuthUser, fileId: string): Promise<ConfigPresetImportPreview> => {
  const bundle = await readConfigPresetImportBundle(context, user, fileId);
  const { types, index } = await computeConfigPresetImportPreviewTypes(context, user, bundle);
  setConfigPresetImportIndex(user.id, fileId, Promise.resolve(index));
  return {
    bundle_name: bundle.metadata.bundle_name,
    openCTI_version: bundle.metadata.openCTI_version,
    generated_at: bundle.metadata.generated_at,
    types,
    ignored: bundle.ignored,
  };
};

// The index of a file: the one the preview kept, else computed now (another node, or what was kept expired) and kept for the next pages
const loadConfigPresetImportIndex = (context: AuthContext, user: AuthUser, fileId: string): Promise<ConfigPresetImportIndex> => {
  const kept = getConfigPresetImportIndex(user.id, fileId);
  if (kept) {
    return kept;
  }
  // Reading the bundle creates the entry the index is kept in. The index is shared by the pages that ask for it: it is not tied to the request
  // that started it, which can be cancelled while another one waits for it.
  const shared = detachConfigPresetImportContext(context);
  const computing = readConfigPresetImportBundle(shared, user, fileId).then(async (bundle) => (await computeConfigPresetImportPreviewTypes(shared, user, bundle)).index);
  setConfigPresetImportIndex(user.id, fileId, computing);
  return computing;
};

// The types of the file that are listed page by page, the ones whose items a dry run does not return
export const listPagedConfigPresetImportTypes = async (context: AuthContext, user: AuthUser, fileId: string): Promise<Set<string>> => {
  return new Set((await loadConfigPresetImportIndex(context, user, fileId)).keys());
};

// One page of the items of a paged type, searched and filtered in memory: nothing is computed, the preview did. The cursor is the position
// of the last item of the page among the matching ones.
export const findConfigPresetImportItems = async (
  context: AuthContext,
  user: AuthUser,
  { file_id: fileId, type, first, after, search, ids, excludedIds, conflictsOnly }: QueryConfigPresetImportItemsArgs,
): Promise<ConfigPresetImportItemConnection> => {
  checkConfigPresetImportAccess(context, user);
  if (!CONFIG_PRESET_FAMILIES.some((family) => family.id === type)) {
    throw FunctionalError('Unknown configuration preset type', { type });
  }
  const items = (await loadConfigPresetImportIndex(context, user, fileId)).get(type);
  if (!items) {
    throw FunctionalError('The type is not listed page by page', { type });
  }
  const idSet = ids ? new Set(ids) : null;
  const excludedSet = excludedIds && excludedIds.length > 0 ? new Set(excludedIds) : null;
  const needle = search?.trim().toLowerCase();
  const matching = items.filter((item) => {
    return (!idSet || idSet.has(item.key))
      && (!excludedSet || !excludedSet.has(item.key))
      && (!conflictsOnly || item.conflict)
      && (!needle || item.label.toLowerCase().includes(needle));
  });
  const offset = Math.max(0, Number.parseInt(after ?? '', 10) || 0);
  const size = Math.min(Math.max(first ?? CONFIG_PRESET_IMPORT_DEFAULT_PAGE_SIZE, 1), CONFIG_PRESET_IMPORT_MAX_PAGE_SIZE);
  const edges = matching.slice(offset, offset + size).map((node, position) => ({ cursor: String(offset + position + 1), node }));
  return {
    edges,
    pageInfo: {
      startCursor: edges[0]?.cursor ?? '',
      endCursor: edges[edges.length - 1]?.cursor ?? '',
      hasNextPage: offset + size < matching.length,
      hasPreviousPage: offset > 0,
      globalCount: matching.length,
    },
  };
};
