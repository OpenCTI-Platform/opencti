import { getSettingsFromDatabase } from '../../../domain/settings';
import { ForbiddenAccess, UnsupportedError } from '../../../config/errors';
import { BYPASS, isUserHasCapability } from '../../../utils/access';
import { getDraftContext } from '../../../utils/draftContext';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { ConfigImportMode } from '../../configImport/configImport-types';
import { CONFIG_PRESET_DEFAULT_IMPORT_MODE, type ConfigPresetImportField } from './configPreset-import-types';

const DATA_URL = /^data:([^;,]+);base64,(.*)$/;

// An image given as a data: URL is shown as its type and size
const describeValue = (value: string) => {
  const match = DATA_URL.exec(value);
  if (!match) {
    return value;
  }
  const bytes = Math.floor((match[2].length * 3) / 4);
  return `${match[1]} (${Math.max(1, Math.round(bytes / 1024))} KB)`;
};

// The fields of an item shown in the preview, in the order of the keys
export const buildImportFields = (configuration: Record<string, unknown>, keys: string[]): ConfigPresetImportField[] => {
  return keys.map((key) => {
    const value = configuration[key];
    return { key, value: typeof value === 'string' ? describeValue(value) : null };
  });
};

export const isNothingToImport = (configuration: Record<string, unknown>, keys: string[]) => {
  return keys.every((key) => configuration[key] === null || configuration[key] === undefined);
};

// The mode of each family of a selection: a family without a mode of its own overwrites
export const configPresetImportModes = (selections: { type: string; mode?: ConfigImportMode | null }[]) => {
  return new Map(selections.flatMap(({ type, mode }) => (mode ? [[type, mode] as const] : [])));
};

export const configPresetImportMode = (modes: Map<string, ConfigImportMode>, type: string) => modes.get(type) ?? CONFIG_PRESET_DEFAULT_IMPORT_MODE;

// What the import of a setting says when it is left as it is, because a type has no copy of it
export const CONFIG_PRESET_ALREADY_EXISTS_REASON = 'Already exists';

// The upload, the preview and the import are BYPASS only and refused in a draft context
export const checkConfigPresetImportAccess = (context: AuthContext, user: AuthUser) => {
  if (!isUserHasCapability(user, BYPASS)) {
    throw ForbiddenAccess();
  }
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot import configuration presets in draft');
  }
};

// internal_id of the Settings: an import session or a running record of another platform is no session and no record
export const getConfigPresetPlatformId = async (context: AuthContext): Promise<string> => (await getSettingsFromDatabase(context))!.internal_id;
