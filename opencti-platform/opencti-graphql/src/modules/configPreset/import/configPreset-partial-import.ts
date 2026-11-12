import { logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import type { FileUploadData } from '../../../database/file-storage';
import type { ConfigPresetImportType, ConfigPresetItemModeInput } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode } from '../../configImport/configImport-types';
import type { ConfigPresetFamilyDefinition } from '../configPreset-types';
import { bundleRefused, CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE, readConfigPresetBundle, readStreamWithLimit, resolveBundleDependencies } from './configPreset-import-bundle';
import { buildConfigPresetImportTypes, computeConfigPresetItems, getConfigPresetFamiliesAvailability } from './configPreset-import-domain';
import { countConfigPresetImportResults, importConfigPresetItem, toConfigPresetImportResult } from './configPreset-import-engine';
import { withConfigPresetImportLock } from './configPreset-import-lock';
import { endConfigPresetImportRunning, findConfigPresetImportRunning, startConfigPresetImportRunning, updateConfigPresetImportRunning } from './configPreset-import-running';
import type { ConfigPresetImportCounts, ConfigPresetImportItemResult } from './configPreset-import-session';
import {
  checkConfigPresetImportAccess,
  checkConfigPresetItemModes,
  configPresetImportMode,
  configPresetImportModes,
  findConfigPresetFamily,
  getConfigPresetFamilyModes,
  pickConfigPresetTypeItems,
  publishConfigPresetImportAction,
  reloadConfigPresetImportUser,
} from './configPreset-import-utils';
import { CONFIG_PRESET_DEFAULT_IMPORT_MODE, type ConfigPresetBundle, type ConfigPresetBundleItem, type ConfigPresetImportPlan } from './configPreset-import-types';

// The partial import: the items of one type (the themes...) taken from a full configuration bundle, from the screen of that type.
// Any family with an importer can be imported this way, nothing is specific to a type here: wiring another screen is front-end only.
// Stateless: the zip comes with each call and is never stored, so it never touches the wizard session nor its pending upload.
// It runs under the lock of the wizard import: never two imports at once on the platform.
// An item that already exists is added as a copy by default, when its type supports it: a partial import adds to the platform.
// Only the items of the type are imported, the dependencies of another type are not: the importer of the item decides what a missing one means.

export interface ConfigPresetPartialImportPreview {
  bundle_name: string | null;
  openCTI_version: string;
  generated_at: string;
  // The type and its items in the bundle, null when the bundle holds none
  type: ConfigPresetImportType | null;
  // The mode of an item in conflict that has none
  default_mode: ConfigImportMode;
}

export interface ConfigPresetPartialImportOutput {
  results: ConfigPresetImportItemResult[];
  counts: ConfigPresetImportCounts;
}

// The family of the type, only one that can be imported: an unknown type is refused as by the wizard
const findImportableFamily = (type: string): ConfigPresetFamilyDefinition => {
  const family = findConfigPresetFamily(type);
  if (!family.importer) {
    throw FunctionalError('This configuration type cannot be imported', { type });
  }
  return family;
};

// The mode of an item that has none: a copy when the type offers it, else the default of the type
export const getConfigPresetPartialImportDefaultMode = (family: ConfigPresetFamilyDefinition): ConfigImportMode => {
  return getConfigPresetFamilyModes(family).includes(ConfigImportMode.Copy) ? ConfigImportMode.Copy : CONFIG_PRESET_DEFAULT_IMPORT_MODE;
};

// Read in memory, never stored: the same limits as the upload of the wizard
const readUploadedBundle = async (file: Promise<FileUploadData>): Promise<{ bundle: ConfigPresetBundle; fileName: string }> => {
  const { createReadStream, filename } = await file;
  const zip = await readStreamWithLimit(createReadStream(), CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE, () => {
    return bundleRefused('The configuration bundle is too large', { limit: CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE });
  });
  return { bundle: await readConfigPresetBundle(zip), fileName: filename };
};

// The items of the family to import: the given ones (every one of the bundle when ids is null), then the items of the same family they
// depend on, dependencies first. The items are picked as by the wizard: an unknown id fails the import.
export const resolveConfigPresetPartialImportItems = (bundle: ConfigPresetBundle, family: ConfigPresetFamilyDefinition, ids: string[] | null): ConfigPresetBundleItem[] => {
  return resolveBundleDependencies(bundle, pickConfigPresetTypeItems(bundle, family.id, ids)).filter((item) => item.type === family.id);
};

// The modes given by the user, checked against the type as by the wizard. An item that has none takes the default of the partial import,
// given to configPresetImportMode when it is read
export const resolveConfigPresetPartialImportModes = (family: ConfigPresetFamilyDefinition, itemModes: ConfigPresetItemModeInput[]): Map<string, ConfigImportMode> => {
  checkConfigPresetItemModes(family, itemModes);
  return configPresetImportModes([{ type: family.id, item_modes: itemModes }]);
};

// Reads only: the items of the type in the bundle, with what already exists. Nothing is written, no audit, and no lock: like the dry run
// of the wizard, it works while an import runs. It is bounded by the limits of the zip.
export const configPresetPartialImportPreview = async (
  context: AuthContext,
  user: AuthUser,
  file: Promise<FileUploadData>,
  type: string,
): Promise<ConfigPresetPartialImportPreview> => {
  checkConfigPresetImportAccess(context, user);
  const family = findImportableFamily(type);
  const { bundle } = await readUploadedBundle(file);
  const items = resolveConfigPresetPartialImportItems(bundle, family, null);
  const availability = await getConfigPresetFamiliesAvailability(context, items);
  const results = await computeConfigPresetItems(context, user, items, { availability, defaultMode: getConfigPresetPartialImportDefaultMode(family) });
  return {
    bundle_name: bundle.metadata.bundle_name,
    openCTI_version: bundle.metadata.openCTI_version,
    generated_at: bundle.metadata.generated_at,
    type: buildConfigPresetImportTypes(bundle, results, availability).find(({ key }) => key === family.id) ?? null,
    default_mode: getConfigPresetPartialImportDefaultMode(family),
  };
};

// Imports the selected items of the type, one by one: a failed item never stops the next one. Audited, no report file (nothing is stored).
// Only the cheap checks run before the lock. The lock is taken before the zip is read, as the real import of the wizard does: a second
// import is refused at once, before its upload is buffered and parsed. The limits of the zip remain a second control.
// The upload may still be arriving when the lock is taken: the lock then covers the end of the upload too, it extends itself meanwhile.
export const configPresetPartialImport = async (
  context: AuthContext,
  user: AuthUser,
  file: Promise<FileUploadData>,
  type: string,
  ids: string[],
  itemModes: ConfigPresetItemModeInput[],
): Promise<ConfigPresetPartialImportOutput> => {
  checkConfigPresetImportAccess(context, user);
  const family = findImportableFamily(type);
  // The import goes on if the browser disconnects: its context is detached from the request
  const importContext: AuthContext = { ...context, requestAbortSignal: undefined };
  return withConfigPresetImportLock(importContext, async (lock) => {
    const { bundle, fileName } = await readUploadedBundle(file);
    const items = resolveConfigPresetPartialImportItems(bundle, family, ids);
    if (items.length === 0) {
      throw FunctionalError('Select at least one configuration item to import');
    }
    const modes = resolveConfigPresetPartialImportModes(family, itemModes);
    const defaultMode = getConfigPresetPartialImportDefaultMode(family);
    // The running record of the wizard, written under the lock like the real import of the wizard does: a wizard import started meanwhile
    // is refused with the name of who imports, a stale applying wizard session reads as interrupted, and the end of the import
    // writes last_finished_at, so that the wizard drops a simulation the import made stale. A failure here stops before any write.
    // The record is written without condition: a callback that lost its lock while it read the zip (the upload may still be arriving)
    // would overwrite, then delete, the record of the import that took over. Checked again just before, nothing is written then.
    if (lock.signal.aborted) {
      throw FunctionalError('Import stopped: lock lost');
    }
    const startedAt = new Date().toISOString();
    await startConfigPresetImportRunning(importContext, user, startedAt, items.length);
    // The same plan as the real import of the wizard: the items that depend on another one of the type get the one written
    const plan: ConfigPresetImportPlan = { created: new Set(), targets: new Map() };
    const results: ConfigPresetImportItemResult[] = [];
    // Why the import stopped writing, when it did: the remaining items fail with it, the processed ones keep their result
    let stopReason: string | null = null;
    try {
      for (let i = 0; i < items.length; i += 1) {
        const item = items[i];
        // A lost lock aborts its signal and throws nothing: checked before each item, the item in progress finishes
        if (!stopReason && lock.signal.aborted) {
          stopReason = 'Import stopped: lock lost';
        }
        // Re-read before each item: a deleted account or a revoked BYPASS stops the writes
        let runUser: AuthUser | undefined;
        if (!stopReason) {
          try {
            runUser = await reloadConfigPresetImportUser(importContext, user);
          } catch (err) {
            stopReason = err instanceof Error ? err.message : String(err);
          }
        }
        if (stopReason || !runUser) {
          // Not processed: the import stopped writing before it
          results.push(toConfigPresetImportResult(item, 'failed', stopReason ?? 'Import stopped'));
        } else {
          try {
            results.push(await importConfigPresetItem(importContext, runUser, item, plan, configPresetImportMode(modes, item.type, item.id, defaultMode)));
          } catch (err) {
            // Only a refused bundle is thrown (an attachment above the extracted size limit): the next items would be read the same way,
            // the import stops as the wizard does. Before any item is written, the refusal is the answer; after, the items written keep
            // their result and the remaining ones fail with the reason
            if (results.length === 0) {
              throw err;
            }
            stopReason = err instanceof Error ? err.message : String(err);
            results.push(toConfigPresetImportResult(item, 'failed', stopReason));
          }
        }
        await updateConfigPresetImportRunning(user, startedAt, results.length);
      }
    } finally {
      // Over once an item has a result, written or failed with the reason the import stopped; the record never outlives the import
      await endConfigPresetImportRunning(user, startedAt, results.length > 0);
    }
    if (stopReason) {
      logApp.warn('[CONFIG PRESET] Partial import stopped before the end', { user_id: user.id, type: family.id, reason: stopReason });
    }
    // Audited whatever the end, for the items already written; no report file, nothing is stored
    const counts = countConfigPresetImportResults(results);
    await publishConfigPresetImportAction(user, { file_id: null, path: '', file_name: fileName, input: { type: family.id, counts } });
    logApp.info('[CONFIG PRESET] Partial import finished', { user_id: user.id, type: family.id, counts });
    return { results, counts };
  }, async (ctx) => (await findConfigPresetImportRunning(ctx, user)).running?.name);
};
