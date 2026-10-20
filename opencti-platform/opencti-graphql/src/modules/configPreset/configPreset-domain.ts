import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { finished } from 'node:stream/promises';
import { ZipArchive } from 'archiver';
import { logApp, PLATFORM_VERSION } from '../../config/conf';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { BYPASS, isUserHasCapability } from '../../utils/access';
import { getDraftContext } from '../../utils/draftContext';
import type { AuthContext, AuthUser } from '../../types/user';
import type {
  ConfigPresetExportableItem,
  ConfigPresetExportableItemConnection,
  ConfigPresetExportableType,
  ConfigPresetSelectionInput,
  QueryConfigPresetExportableItemsArgs,
} from '../../generated/graphql';
import { deleteFile, type LoadedFile, uploadToStorage } from '../../database/file-storage';
import { allFilesForPaths } from '../internal/document/document-domain';
import { CONFIG_PRESET_STORAGE_PATH } from '../internal/document/document-types';
import { type ConfigPresetExportSummary, publishUserAction } from '../../listener/UserActionListener';
import { addConfigPresetExportCount } from '../../manager/telemetryManager';
import { CONFIG_PRESET_FAMILIES, configPresetItemFilePath, exportConfigPresetItem } from './configPreset-registry';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from './configPreset-types';
import { buildConfigPresetFileName, sanitizeBundleName } from './configPreset-utils';

// The dialog shows a type inline when its first page is its only one
export const CONFIG_PRESET_FIRST_PAGE_SIZE = 10;

const toExportableItem = (item: ConfigPresetItemDefinition): ConfigPresetExportableItem => ({
  key: item.id,
  label: item.label,
  translatable: item.translatable,
});

const findConfigPresetFamily = (type: string) => {
  const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === type);
  if (!family) {
    throw FunctionalError('Unknown configuration preset type', { type });
  }
  return family;
};

export const findConfigPresetExportableTypes = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetExportableType[]> => {
  const types = await Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
    const page = await family.listItems(context, user, { first: CONFIG_PRESET_FIRST_PAGE_SIZE });
    return {
      key: family.id,
      label: family.label,
      description: family.description,
      group: { key: family.group.id, label: family.group.label },
      items: page.edges.map(({ node }) => toExportableItem(node)),
      itemsPageInfo: page.pageInfo,
    };
  }));
  // A category with nothing to export on this platform (no message set) is not shown
  return types.filter((type) => type.itemsPageInfo.globalCount > 0);
};

export const findConfigPresetExportableItems = async (
  context: AuthContext,
  user: AuthUser,
  { type, ...args }: QueryConfigPresetExportableItemsArgs,
): Promise<ConfigPresetExportableItemConnection> => {
  const page = await findConfigPresetFamily(type).listItems(context, user, args);
  return { ...page, edges: page.edges.map(({ cursor, node }) => ({ cursor, node: toExportableItem(node) })) };
};

export const CONFIG_PRESET_METADATA_FILE = 'metadata.json';
export const CONFIG_PRESET_EXPORT_RETENTION_MS = 60 * 60 * 1000;

type SelectedConfigPresetFamily = ConfigPresetFamilyDefinition & { items: ConfigPresetItemDefinition[] };

// Keeps the registry order, merges duplicated types and rejects anything the registry does not know.
// A selection without items (null) takes every item the family lists at export time but its excluded_items;
// an empty list takes none. Selections of the same type add up.
export const resolveConfigPresetSelections = async (
  context: AuthContext,
  user: AuthUser,
  selections: ConfigPresetSelectionInput[],
): Promise<SelectedConfigPresetFamily[]> => {
  selections.forEach(({ type, items, excluded_items }) => {
    findConfigPresetFamily(type);
    if (items && excluded_items && excluded_items.length > 0) {
      throw FunctionalError('Excluded items require a selection of every item of the type', { type });
    }
  });
  const resolved: SelectedConfigPresetFamily[] = [];
  for (let i = 0; i < CONFIG_PRESET_FAMILIES.length; i += 1) {
    const family = CONFIG_PRESET_FAMILIES[i];
    const familySelections = selections.filter(({ type }) => type === family.id);
    if (familySelections.length > 0) {
      const requestedIds = [...new Set(familySelections.flatMap(({ items }) => items ?? []))];
      let items = requestedIds.length > 0 ? await family.resolveItems(context, user, requestedIds, []) : [];
      const resolvedIds = new Set(items.map((item) => item.id));
      const unknownId = requestedIds.find((itemId) => !resolvedIds.has(itemId));
      if (unknownId) {
        throw FunctionalError('Unknown configuration preset item', { type: family.id, item: unknownId });
      }
      const exclusions = familySelections.filter(({ items: selectedItems }) => !selectedItems).map(({ excluded_items }) => excluded_items ?? []);
      if (exclusions.length > 0) {
        // Excluded only when every selection of all the items excludes it and no list selects it
        const [firstExclusion, ...otherExclusions] = exclusions;
        const excludedIds = firstExclusion.filter((itemId) => otherExclusions.every((ids) => ids.includes(itemId)) && !requestedIds.includes(itemId));
        items = await family.resolveItems(context, user, null, excludedIds);
      }
      if (items.length > 0) {
        resolved.push({ ...family, items });
      }
    }
  }
  if (resolved.length === 0) {
    throw FunctionalError('Select at least one configuration item to export');
  }
  return resolved;
};

// Called by the garbage collection manager. A failed deletion does not stop the others: the next run retries it.
// Lists everything under config_preset/, the folder of each export included.
export const deleteExpiredConfigPresetExports = async (context: AuthContext, user: AuthUser) => {
  try {
    const notModifiedSince = new Date(Date.now() - CONFIG_PRESET_EXPORT_RETENTION_MS).toISOString();
    const expiredFiles = await allFilesForPaths(context, user, [CONFIG_PRESET_STORAGE_PATH], { notModifiedSince });
    for (let i = 0; i < expiredFiles.length; i += 1) {
      const fileId = expiredFiles[i].id;
      try {
        await deleteFile(context, user, fileId);
      } catch (err) {
        logApp.warn('[CONFIG PRESET] Failed to delete an expired export', { cause: err, file_id: fileId });
      }
    }
  } catch (err) {
    logApp.warn('[CONFIG PRESET] Failed to delete expired exports', { cause: err });
  }
};

// Content of metadata.json
interface ConfigPresetMetadata {
  openCTI_version: string;
  generated_at: string;
  bundle_name: string | null;
}

const writeConfigPresetZip = async (
  context: AuthContext,
  user: AuthUser,
  families: SelectedConfigPresetFamily[],
  zipPath: string,
  metadataBase: Pick<ConfigPresetMetadata, 'generated_at' | 'bundle_name'>,
): Promise<ConfigPresetExportSummary> => {
  const archive = new ZipArchive();
  // Readable by the platform user only
  const output = fs.createWriteStream(zipPath, { mode: 0o600 });
  const written = new Promise<void>((resolve, reject) => {
    output.on('close', resolve);
    output.on('error', reject);
    archive.on('error', reject);
  });
  // A stream error can happen while the items are exported, before written is awaited: never an unhandled rejection,
  // and the remaining items are not exported
  let streamError: unknown;
  written.catch((err) => {
    streamError = err;
  });
  archive.pipe(output);
  try {
    const counts: Record<string, number> = {};
    for (let i = 0; i < families.length; i += 1) {
      const family = families[i];
      counts[family.id] = 0;
      for (let j = 0; j < family.items.length; j += 1) {
        if (streamError) {
          throw streamError;
        }
        const item = family.items[j];
        const file = await exportConfigPresetItem(context, user, family, item);
        archive.append(JSON.stringify(file, null, 2), { name: configPresetItemFilePath(family, item) });
        counts[family.id] += 1;
      }
    }
    const metadata: ConfigPresetMetadata = {
      openCTI_version: PLATFORM_VERSION,
      generated_at: metadataBase.generated_at,
      bundle_name: metadataBase.bundle_name,
    };
    archive.append(JSON.stringify(metadata, null, 2), { name: CONFIG_PRESET_METADATA_FILE });
    // Awaited together: when the output fails, the archive is no longer drained and finalize never resolves
    await Promise.all([archive.finalize(), written]);
    return {
      entity_types: families.map((family) => family.id),
      counts,
      // The items written in the zip, in registry order
      items: Object.fromEntries(families.map((family) => [family.id, family.items.map((item) => item.id)])),
    };
  } catch (err) {
    // The original error is the one reported, a stream error caused by the abort is ignored
    archive.abort();
    output.destroy();
    // Wait for the file to be closed, otherwise it could be created after the caller removed it
    await finished(output).catch(() => undefined);
    throw err;
  }
};

export const configPresetExport = async (
  context: AuthContext,
  user: AuthUser,
  selections: ConfigPresetSelectionInput[],
  bundleName?: string | null,
): Promise<LoadedFile> => {
  if (!isUserHasCapability(user, BYPASS)) {
    throw ForbiddenAccess();
  }
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot export configuration presets in draft');
  }
  const families = await resolveConfigPresetSelections(context, user, selections);
  const generatedAt = new Date();
  const fileName = buildConfigPresetFileName(generatedAt);
  // Each export in its own folder, like support packages
  const exportFolder = `${CONFIG_PRESET_STORAGE_PATH}/${crypto.randomUUID()}`;
  const tmpZipPath = path.join(os.tmpdir(), `opencti-config-preset-${crypto.randomUUID()}.zip`);
  try {
    const summary = await writeConfigPresetZip(context, user, families, tmpZipPath, {
      generated_at: generatedAt.toISOString(),
      bundle_name: sanitizeBundleName(bundleName),
    });
    const { upload } = await uploadToStorage(
      context,
      user,
      exportFolder,
      { createReadStream: () => fs.createReadStream(tmpZipPath), filename: fileName },
      { noTriggerImport: true, meta: { description: 'Configuration preset export' } },
    );
    // The zip is already stored: if the publication fails, the export stays as an orphan until
    // the garbage collection manager removes it once expired
    await publishUserAction({
      user,
      event_type: 'command',
      event_access: 'administration',
      event_scope: 'export',
      context_data: {
        path: exportFolder,
        file_name: upload.name,
        input: summary,
      },
    });
    addConfigPresetExportCount();
    return upload;
  } finally {
    await fs.promises.rm(tmpZipPath, { force: true }).catch((err) => {
      logApp.warn('[CONFIG PRESET] Failed to remove the temporary export file', { cause: err, tmpZipPath });
    });
  }
};
