import crypto from 'node:crypto';
import { Transform } from 'node:stream';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { downloadFile } from '../../database/raw-file-storage';
import { deleteFile, type FileUploadData, loadFile, type LoadedFile, uploadToStorage } from '../../database/file-storage';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetImportPreview } from '../../generated/graphql';
import { allFilesForPaths } from '../internal/document/document-domain';
import { CONFIG_PRESET_IMPORT_PATH } from '../internal/document/document-types';
import { CONFIG_PRESET_FAMILIES, configPresetFamilyType, configPresetRequiresEnterpriseEdition } from './configPreset-registry';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { checkConfigPresetImportAccess, getConfigPresetPlatformId } from './configPreset-import-utils';
import { applyConfigPresetImportEvent, checkConfigPresetImportNotApplying } from './configPreset-import-session-domain';
import { CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE, type ConfigPresetItemKey, readConfigPresetBundle, readStreamWithLimit, resolveBundleDependencies } from './configPreset-import-bundle';
import {
  CONFIG_PRESET_REASON_FILE_MISSING,
  type ConfigPresetBundle,
  type ConfigPresetBundleItem,
  type ConfigPresetComputedItem,
  type ConfigPresetImportPlan,
} from './configPreset-import-types';

const fileMissing = () => FunctionalError('The uploaded file no longer exists', { reason: CONFIG_PRESET_REASON_FILE_MISSING });

// A transform that fails as soon as more than the limit goes through, so an oversized upload is not stored
const limitStream = (limit: number) => {
  let size = 0;
  return new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.length;
      callback(size > limit ? FunctionalError('The configuration bundle is too large', { reason: 'bundle_refused', limit }) : null, chunk);
    },
  });
};

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

export const configPresetImportUpload = async (context: AuthContext, user: AuthUser, file: Promise<FileUploadData>): Promise<LoadedFile> => {
  checkConfigPresetImportAccess(context, user);
  // Refused before anything is stored: the deletion of the previous uploads would delete the zip being imported
  await checkConfigPresetImportNotApplying(context, user);
  const { createReadStream, filename } = await file;
  const { upload } = await uploadToStorage(
    context,
    user,
    `${CONFIG_PRESET_IMPORT_PATH}/${crypto.randomUUID()}`,
    { createReadStream: () => createReadStream().pipe(limitStream(CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE)), filename },
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

// compute of every item, required dependencies first: reads only, the plan records what would be created
// An item that needs the Enterprise Edition is skipped on a Community platform, before anything else is decided about it
export const CONFIG_PRESET_EE_REQUIRED_REASON = 'Enterprise Edition required';

export const skipEnterpriseEditionItem = (item: ConfigPresetBundleItem): ConfigPresetComputedItem => ({
  status: 'skipped',
  reason: CONFIG_PRESET_EE_REQUIRED_REASON,
  label: item.id,
  translatable: false,
  exists: true,
  fields: [],
});

// skipEnterpriseEdition: a dry run skips the items that need the Enterprise Edition on a Community platform, the preview does not
export const computeConfigPresetItems = async (
  context: AuthContext,
  user: AuthUser,
  items: ConfigPresetBundleItem[],
  { skipEnterpriseEdition = false }: { skipEnterpriseEdition?: boolean } = {},
): Promise<{ item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[]> => {
  const plan: ConfigPresetImportPlan = { created: new Set() };
  const results: { item: ConfigPresetBundleItem; computed: ConfigPresetComputedItem }[] = [];
  // Read once per run
  const isEE = skipEnterpriseEdition ? await isEnterpriseEdition(context) : true;
  for (let i = 0; i < items.length; i += 1) {
    const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === items[i].type)!;
    const computed = !isEE && configPresetRequiresEnterpriseEdition(items[i].type, items[i].id)
      ? skipEnterpriseEditionItem(items[i])
      : await family.importer!.compute(context, user, items[i], plan);
    results.push({ item: items[i], computed });
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
  const types = CONFIG_PRESET_FAMILIES.filter((family) => results.some(({ item }) => item.type === family.id)).map((family) => ({
    key: family.id,
    label: family.label,
    description: family.description,
    group: { key: family.group.id, label: family.group.label },
    items: results.filter(({ item }) => item.type === family.id).map(({ item, computed }) => {
      const dependencyPaths = Object.values(bundle.dependencies[configPresetFamilyType(family)]?.[item.id] ?? {});
      return {
        key: item.id,
        label: computed.label,
        translatable: computed.translatable,
        isDefault: family.id === 'branding' && defaultThemeId?.standard_id === item.id,
        exists: computed.exists,
        // Static: the front disables the item on a Community platform, whatever it knows of the license
        requiresEnterpriseEdition: configPresetRequiresEnterpriseEdition(family.id, item.id),
        fields: computed.fields,
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
