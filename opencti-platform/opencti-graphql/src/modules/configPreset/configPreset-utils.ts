import { PLATFORM_VERSION } from '../../config/conf';
import type { UserConfigPresetExportActionContextData, UserConfigPresetImportActionContextData } from '../../listener/UserActionListener';

// The files of a bundle that are not items
export const CONFIG_PRESET_METADATA_FILE = 'metadata.json';
export const CONFIG_PRESET_DEPENDENCIES_FILE = 'dependencies.json';

const BUNDLE_NAME_MAX_LENGTH = 80;

// Letters with their combining marks (accents, Indic vowel signs), digits, ZWNJ / ZWJ (Persian, Indic scripts),
// spaces and . _ - ( ); everything else, control and format characters included, is removed
// eslint-disable-next-line no-misleading-character-class -- ZWNJ and ZWJ are allowed on their own, not as part of a joined sequence
const BUNDLE_NAME_FORBIDDEN_CHARACTERS = /[^\p{L}\p{M}\p{N}‌‍ ._()-]/gu;

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

// Message of the activity log of an export: the file and the number of items exported per type
export const buildConfigPresetExportMessage = ({ file_name, input: { entity_types, counts } }: UserConfigPresetExportActionContextData) => {
  const exported = entity_types.map((type) => `${type}: ${counts[type] ?? 0}`).join(', ');
  return `exports the configuration preset \`${file_name}\` (${exported})`;
};

// Message of the activity log of an import: the file and the number of items per result
export const buildConfigPresetImportMessage = ({ file_name, input: { counts } }: UserConfigPresetImportActionContextData) => {
  return `imports a configuration preset (created: ${counts.created}, overwritten: ${counts.overwritten}, skipped: ${counts.skipped}, failed: ${counts.failed}), report \`${file_name}\``;
};
