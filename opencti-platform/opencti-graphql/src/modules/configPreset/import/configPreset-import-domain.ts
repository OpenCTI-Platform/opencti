import crypto from 'node:crypto';
import { logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { downloadFile } from '../../../database/raw-file-storage';
import { deleteFile, type FileUploadData, loadFile, type LoadedFile, uploadToStorage } from '../../../database/file-storage';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { ConfigPresetImportPreview } from '../../../generated/graphql';
import type { ConfigImportMode } from '../../configImport/configImport-types';
import { allFilesForPaths } from '../../internal/document/document-domain';
import { CONFIG_PRESET_HISTORY_PATH, CONFIG_PRESET_IMPORT_PATH } from '../../internal/document/document-types';
import type { ConfigPresetFamilyDefinition } from '../configPreset-types';
import { CONFIG_PRESET_FAMILIES, configPresetFamilyType, isConfigPresetFamilyAvailable } from '../configPreset-registry';
import { checkConfigPresetImportAccess, configPresetImportMode, getConfigPresetPlatformId } from './configPreset-import-utils';
import { applyConfigPresetImportEvent, checkConfigPresetImportNotApplying } from './configPreset-import-session-domain';
import {
  CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE,
  type ConfigPresetItemKey,
  limitStream,
  readConfigPresetBundle,
  readStreamWithLimit,
  resolveBundleDependencies,
} from './configPreset-import-bundle';
import {
  CONFIG_PRESET_DEFAULT_IMPORT_MODE,
  CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED,
  CONFIG_PRESET_REASON_FILE_MISSING,
  type ConfigPresetBundle,
  type ConfigPresetBundleItem,
  type ConfigPresetComputedItem,
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

export const readConfigPresetImportBundle = async (context: AuthContext, user: AuthUser, fileId: string): Promise<ConfigPresetBundle> => {
  checkConfigPresetImportAccess(context, user);
  return readConfigPresetBundle(await loadConfigPresetImportZip(context, user, fileId));
};

// What the importer of the family decides for an item. A family that requires the Enterprise Edition skips its items on a platform
// without it. The platform is read at each call: a license applied since the preview is taken into account by the next
// computation, and the real import computes before it writes.
export const computeConfigPresetItem = async (
  context: AuthContext,
  user: AuthUser,
  family: ConfigPresetFamilyDefinition,
  item: ConfigPresetBundleItem,
  plan: ConfigPresetImportPlan,
  mode: ConfigImportMode,
): Promise<ConfigPresetComputedItem> => {
  // The importer of a family the platform cannot import is never called: it may read through domain functions that refuse without
  // the Enterprise Edition, and what it would validate or find is of no use. The item is named after its family.
  if (!(await isConfigPresetFamilyAvailable(context, family))) {
    return { label: family.label, translatable: true, exists: false, conflict: false, status: 'skipped', reason: CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED };
  }
  return family.importer!.compute(context, user, item, plan, mode);
};

// compute of every item, required dependencies first: reads only, the plan records what would be created
// modes: the mode of each item, OVERWRITE for the items that have none (the preview, the dependencies)
export const computeConfigPresetItems = async (
  context: AuthContext,
  user: AuthUser,
  items: ConfigPresetBundleItem[],
  { modes = new Map() }: { modes?: Map<string, ConfigImportMode> } = {},
): Promise<{ item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[]> => {
  const plan: ConfigPresetImportPlan = { created: new Set(), themeNames: new Set(), releasedThemeNames: new Set() };
  const results: { item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[] = [];
  for (let i = 0; i < items.length; i += 1) {
    const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === items[i].type)!;
    const mode = configPresetImportMode(modes, items[i].type, items[i].id);
    results.push({ item: items[i], computed: await computeConfigPresetItem(context, user, family, items[i], plan, mode) });
  }
  return results;
};

// The items of the zip per family, with what already exists, the values they would write and their required dependencies
export const configPresetImportPreview = async (context: AuthContext, user: AuthUser, fileId: string): Promise<ConfigPresetImportPreview> => {
  const bundle = await readConfigPresetImportBundle(context, user, fileId);
  const keys: ConfigPresetItemKey[] = bundle.items;
  const ordered = resolveBundleDependencies(bundle, keys);
  const results = await computeConfigPresetItems(context, user, ordered);
  const defaultThemeId = bundle.items.find((item) => item.type === 'platform')?.configuration.default_theme as { standard_id?: string } | null | undefined;
  const families = CONFIG_PRESET_FAMILIES.filter((family) => results.some(({ item }) => item.type === family.id));
  const availability = await Promise.all(families.map((family) => isConfigPresetFamilyAvailable(context, family)));
  const types = families.map((family, index) => ({
    key: family.id,
    label: family.label,
    description: family.description,
    group: { key: family.group.id, label: family.group.label },
    lockedByEnterpriseEdition: !availability[index],
    modes: family.importModes ?? [CONFIG_PRESET_DEFAULT_IMPORT_MODE],
    // The items of a family the platform cannot import are not shown: the dialog shows the type as locked
    items: !availability[index] ? [] : results.filter(({ item }) => item.type === family.id).map(({ item, computed }) => {
      const dependencyPaths = Object.values(bundle.dependencies[configPresetFamilyType(family)]?.[item.id] ?? {});
      return {
        key: item.id,
        label: computed.label,
        translatable: computed.translatable,
        isDefault: family.id === 'branding' && defaultThemeId?.standard_id === item.id,
        exists: computed.exists,
        conflict: computed.conflict,
        fields: computed.fields ?? [],
        dependsOn: bundle.items
          .filter((dependency) => dependencyPaths.includes(dependency.path))
          .map((dependency) => ({ type: dependency.type, key: dependency.id })),
      };
    }),
  }));
  return {
    bundle_name: bundle.metadata.bundle_name,
    openCTI_version: bundle.metadata.openCTI_version,
    generated_at: bundle.metadata.generated_at,
    types,
    ignored: bundle.ignored,
  };
};
