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
import type { ConfigPresetExportableType, ConfigPresetSelectionInput } from '../../generated/graphql';
import { deleteFile, type LoadedFile, uploadToStorage } from '../../database/file-storage';
import { allFilesForPaths } from '../internal/document/document-domain';
import { CONFIG_PRESET_STORAGE_PATH } from '../internal/document/document-types';
import { type ConfigPresetExportSummary, publishUserAction } from '../../listener/UserActionListener';
import { addConfigPresetExportCount } from '../../manager/telemetryManager';
import { CONFIG_PRESET_FAMILIES, configPresetItemFilePath, exportConfigPresetItem } from './configPreset-registry';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from './configPreset-types';
import { buildConfigPresetFileName, sanitizeBundleName } from './configPreset-utils';

export const findConfigPresetExportableTypes = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetExportableType[]> => {
  return Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
    const items = await family.listItems(context, user);
    return {
      key: family.id,
      label: family.label,
      group: { key: family.group.id, label: family.group.label },
      items: items.map(({ id, label, translatable }) => ({ key: id, label, translatable })),
    };
  }));
};

export const CONFIG_PRESET_METADATA_FILE = 'metadata.json';
export const CONFIG_PRESET_EXPORT_RETENTION_MS = 60 * 60 * 1000;

type SelectedConfigPresetFamily = ConfigPresetFamilyDefinition & { items: ConfigPresetItemDefinition[] };

// Keeps the registry order, merges duplicated types and rejects anything the registry does not know.
// A selection without items (null) takes every item the family lists at export time; an empty list takes none.
export const resolveConfigPresetSelections = async (
  context: AuthContext,
  user: AuthUser,
  selections: ConfigPresetSelectionInput[],
): Promise<SelectedConfigPresetFamily[]> => {
  selections.forEach(({ type }) => {
    if (!CONFIG_PRESET_FAMILIES.some((family) => family.id === type)) {
      throw FunctionalError('Unknown configuration preset type', { type });
    }
  });
  const resolved: SelectedConfigPresetFamily[] = [];
  for (let i = 0; i < CONFIG_PRESET_FAMILIES.length; i += 1) {
    const family = CONFIG_PRESET_FAMILIES[i];
    const familySelections = selections.filter(({ type }) => type === family.id);
    if (familySelections.length > 0) {
      const familyItems = await family.listItems(context, user);
      const familyItemIds = new Set(familyItems.map((item) => item.id));
      const requestedIds = new Set(familySelections.flatMap(({ items }) => items ?? []));
      requestedIds.forEach((itemId) => {
        if (!familyItemIds.has(itemId)) {
          throw FunctionalError('Unknown configuration preset item', { type: family.id, item: itemId });
        }
      });
      const selectAll = familySelections.some(({ items }) => !items);
      const items = selectAll ? familyItems : familyItems.filter((item) => requestedIds.has(item.id));
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
