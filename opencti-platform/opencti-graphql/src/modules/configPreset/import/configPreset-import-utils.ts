import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import type { BasicStoreSettings } from '../../../types/settings';
import { ForbiddenAccess, UnsupportedError } from '../../../config/errors';
import { BYPASS, isUserHasCapability, SYSTEM_USER } from '../../../utils/access';
import { getDraftContext } from '../../../utils/draftContext';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { ConfigImportMode } from '../../configImport/configImport-types';
import { CONFIG_PRESET_DEFAULT_IMPORT_MODE, configPresetPlanKey } from './configPreset-import-types';

// The mode of each item of a selection, by `<type>/<bundle id>`: an item that has none overwrites
export const configPresetImportModes = (selections: { type: string; item_modes?: { key: string; mode: ConfigImportMode }[] | null }[]) => {
  return new Map(selections.flatMap(({ type, item_modes: itemModes }) => (itemModes ?? []).map(({ key, mode }) => [configPresetPlanKey(type, key), mode] as const)));
};

export const configPresetImportMode = (modes: Map<string, ConfigImportMode>, type: string, id: string) => {
  return modes.get(configPresetPlanKey(type, id)) ?? CONFIG_PRESET_DEFAULT_IMPORT_MODE;
};

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
// The id of the platform settings never changes: read from the cache, as the session and the running record are read by the polling of the wizard
export const getConfigPresetPlatformId = async (context: AuthContext): Promise<string> => {
  return (await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS)).internal_id;
};
