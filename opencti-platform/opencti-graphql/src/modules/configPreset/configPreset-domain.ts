import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { finished } from 'node:stream/promises';
import { ZipArchive } from 'archiver';
import { CONFIG_PRESET_FEATURE_FLAG, logApp, PLATFORM_VERSION } from '../../config/conf';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { BYPASS, enforceEnableFeatureFlag, isUserHasCapability } from '../../utils/access';
import { getDraftContext } from '../../utils/draftContext';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetExportableType, ConfigPresetSelectionInput } from '../../generated/graphql';
import { deleteFile, type LoadedFile, uploadToStorage } from '../../database/file-storage';
import { allFilesForPaths } from '../internal/document/document-domain';
import { CONFIG_PRESET_STORAGE_PATH } from '../internal/document/document-types';
import { buildContextDataForFile, publishUserAction } from '../../listener/UserActionListener';
import { addConfigPresetExportCount } from '../../manager/telemetryManager';
import { CONFIG_PRESET_FAMILIES, configPresetItemFilePath, exportConfigPresetItem } from './configPreset-registry';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from './configPreset-types';

export const findConfigPresetExportableTypes = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetExportableType[]> => {
  enforceEnableFeatureFlag(CONFIG_PRESET_FEATURE_FLAG);
  return Promise.all(CONFIG_PRESET_FAMILIES.map(async (family) => {
    const items = await family.listItems(context, user);
    return {
      id: family.id,
      label: family.label,
      group: family.group,
      items: items.map(({ id, label, translatable }) => ({ id, label, translatable })),
    };
  }));
};

export const CONFIG_PRESET_METADATA_FILE = 'metadata.json';
export const CONFIG_PRESET_EXPORT_RETENTION_MS = 60 * 60 * 1000;
const BUNDLE_NAME_MAX_LENGTH = 80;

// Letters with their combining marks (accents, Indic vowel signs), digits, ZWNJ / ZWJ (Persian, Indic scripts),
// spaces and . _ - ( ); everything else, control and format characters included, is removed
// eslint-disable-next-line no-misleading-character-class -- ZWNJ and ZWJ are allowed on their own, not as part of a joined sequence
const BUNDLE_NAME_FORBIDDEN_CHARACTERS = /[^\p{L}\p{M}\p{N}\u200C\u200D ._()-]/gu;

export const sanitizeBundleName = (bundleName?: string | null): string | null => {
  const cleaned = (bundleName ?? '')
    .normalize('NFC')
    .replace(BUNDLE_NAME_FORBIDDEN_CHARACTERS, '')
    .replace(/ {2,}/g, ' ')
    .trim();
  // Cut by code points, so a character outside the BMP is never split in two
  const sanitized = Array.from(cleaned).slice(0, BUNDLE_NAME_MAX_LENGTH).join('').trim();
  return sanitized.length > 0 ? sanitized : null;
};

// UTC date and time; each export also gets its own folder, so two exports in the same second do not collide
export const buildConfigPresetFileName = (date: Date) => {
  const iso = date.toISOString();
  const day = iso.slice(0, 10).replaceAll('-', '');
  const time = iso.slice(11, 19).replaceAll(':', '');
  return `opencti-config-${day}-${time}-${PLATFORM_VERSION}.zip`;
};

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
      const requestedIds = new Set(familySelections.flatMap(({ items }) => items ?? []));
      requestedIds.forEach((itemId) => {
        if (!familyItems.some((item) => item.id === itemId)) {
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

// A failed cleanup must not prevent the export: the next export retries it.
// Lists everything under config_preset/, the folder of each export included.
const deleteExpiredConfigPresetExports = async (context: AuthContext, user: AuthUser) => {
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

interface ConfigPresetMetadata {
  openCTI_version: string;
  generated_at: string;
  generated_by: string;
  entity_types: string[];
  counts: Record<string, number>;
  requested_counts: Record<string, number>;
  items: Record<string, string[]>;
  bundle_name: string | null;
}

const writeConfigPresetZip = async (
  context: AuthContext,
  user: AuthUser,
  families: SelectedConfigPresetFamily[],
  zipPath: string,
  metadataBase: Pick<ConfigPresetMetadata, 'generated_at' | 'bundle_name'>,
): Promise<ConfigPresetMetadata> => {
  const archive = new ZipArchive();
  // Readable by the platform user only
  const output = fs.createWriteStream(zipPath, { mode: 0o600 });
  const written = new Promise<void>((resolve, reject) => {
    output.on('close', resolve);
    output.on('error', reject);
    archive.on('error', reject);
  });
  // A stream error can happen while the items are exported, before written is awaited: never an unhandled rejection
  written.catch(() => undefined);
  archive.pipe(output);
  try {
    const counts: Record<string, number> = {};
    const requestedCounts: Record<string, number> = {};
    for (let i = 0; i < families.length; i += 1) {
      const family = families[i];
      requestedCounts[family.id] = family.items.length;
      counts[family.id] = 0;
      for (let j = 0; j < family.items.length; j += 1) {
        const item = family.items[j];
        const file = await exportConfigPresetItem(context, user, family, item);
        archive.append(JSON.stringify(file, null, 2), { name: configPresetItemFilePath(family, item) });
        counts[family.id] += 1;
      }
    }
    const metadata: ConfigPresetMetadata = {
      openCTI_version: PLATFORM_VERSION,
      generated_at: metadataBase.generated_at,
      generated_by: user.id,
      entity_types: families.map((family) => family.id),
      counts,
      requested_counts: requestedCounts,
      // The items written in the zip, in registry order
      items: Object.fromEntries(families.map((family) => [family.id, family.items.map((item) => item.id)])),
      bundle_name: metadataBase.bundle_name,
    };
    archive.append(JSON.stringify(metadata, null, 2), { name: CONFIG_PRESET_METADATA_FILE });
    // Awaited together: when the output fails, the archive is no longer drained and finalize never resolves
    await Promise.all([archive.finalize(), written]);
    return metadata;
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
  enforceEnableFeatureFlag(CONFIG_PRESET_FEATURE_FLAG);
  if (!isUserHasCapability(user, BYPASS)) {
    throw ForbiddenAccess();
  }
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot export configuration presets in draft');
  }
  const families = await resolveConfigPresetSelections(context, user, selections);
  await deleteExpiredConfigPresetExports(context, user);
  const generatedAt = new Date();
  const fileName = buildConfigPresetFileName(generatedAt);
  // Each export in its own folder, like support packages
  const exportFolder = `${CONFIG_PRESET_STORAGE_PATH}/${crypto.randomUUID()}`;
  const tmpZipPath = path.join(os.tmpdir(), `opencti-config-preset-${crypto.randomUUID()}.zip`);
  try {
    const metadata = await writeConfigPresetZip(context, user, families, tmpZipPath, {
      generated_at: generatedAt.toISOString(),
      bundle_name: sanitizeBundleName(bundleName),
    });
    const { upload } = await uploadToStorage(
      context,
      user,
      exportFolder,
      { createReadStream: () => fs.createReadStream(tmpZipPath), filename: fileName, mimeType: 'application/zip' },
      { noTriggerImport: true, meta: { description: 'Configuration preset export' } },
    );
    const contextData = buildContextDataForFile(null, exportFolder, upload.name, [], {
      entity_types: metadata.entity_types,
      counts: metadata.counts,
      items: metadata.items,
    });
    await publishUserAction({
      user,
      event_type: 'file',
      event_access: 'administration',
      event_scope: 'create',
      context_data: contextData,
    });
    addConfigPresetExportCount();
    return upload;
  } finally {
    await fs.promises.rm(tmpZipPath, { force: true }).catch((err) => {
      logApp.warn('[CONFIG PRESET] Failed to remove the temporary export file', { cause: err, tmpZipPath });
    });
  }
};
