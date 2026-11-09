import { getEntityFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import type { BasicStoreSettings } from '../../../types/settings';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../../config/errors';
import { BYPASS, isUserHasCapability, SYSTEM_USER } from '../../../utils/access';
import { getDraftContext } from '../../../utils/draftContext';
import type { AuthContext, AuthUser } from '../../../types/user';
import { logApp } from '../../../config/conf';
import { publishUserAction, type UserConfigPresetImportActionContextData } from '../../../listener/UserActionListener';
import type { ConfigImportMode } from '../../configImport/configImport-types';
import { resolveUserByIdFromCache } from '../../user/user-domain';
import { CONFIG_PRESET_FAMILIES } from '../configPreset-registry';
import type { ConfigPresetFamilyDefinition } from '../configPreset-types';
import { CONFIG_PRESET_DEFAULT_IMPORT_MODE, type ConfigPresetBundle, type ConfigPresetBundleItem, configPresetPlanKey } from './configPreset-import-types';

// The family of a type of a selection: the type sent by the frontend is not trusted
export const findConfigPresetFamily = (type: string): ConfigPresetFamilyDefinition => {
  const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === type);
  if (!family) {
    throw FunctionalError('Unknown configuration preset type', { type });
  }
  return family;
};

// What an import can do with the items of the family that already exist
export const getConfigPresetFamilyModes = (family: ConfigPresetFamilyDefinition): ConfigImportMode[] => {
  return family.importModes ?? [CONFIG_PRESET_DEFAULT_IMPORT_MODE];
};

// The modes of a selection are ones the family offers
export const checkConfigPresetItemModes = (family: ConfigPresetFamilyDefinition, itemModes: { key: string; mode: ConfigImportMode }[] | null | undefined) => {
  const supported = getConfigPresetFamilyModes(family);
  (itemModes ?? []).forEach(({ key, mode }) => {
    if (!supported.includes(mode)) {
      throw FunctionalError('Unsupported import mode for this configuration preset type', { type: family.id, item: key, mode });
    }
  });
};

// The items of a type in the bundle: the given ones, every one but the excluded ones when items is null. The ids sent by the frontend
// are not trusted: an unknown one fails the import, an unknown excluded one is ignored
export const pickConfigPresetTypeItems = (
  bundle: ConfigPresetBundle,
  type: string,
  items: string[] | null | undefined,
  excludedItems: string[] | null | undefined = [],
): ConfigPresetBundleItem[] => {
  const available = bundle.items.filter((item) => item.type === type);
  if (!items) {
    return available.filter((item) => !(excludedItems ?? []).includes(item.id));
  }
  return items.map((id) => {
    const item = available.find((candidate) => candidate.id === id);
    if (!item) {
      throw FunctionalError('Unknown configuration preset item', { type, item: id });
    }
    return item;
  });
};

// The mode of each item of a selection, by `<type>/<bundle id>`
export const configPresetImportModes = (selections: { type: string; item_modes?: { key: string; mode: ConfigImportMode }[] | null }[]) => {
  return new Map(selections.flatMap(({ type, item_modes: itemModes }) => (itemModes ?? []).map(({ key, mode }) => [configPresetPlanKey(type, key), mode] as const)));
};

// The mode of an item, the default one when it has none: OVERWRITE for the wizard, COPY for a partial import of a type that offers it
export const configPresetImportMode = (modes: Map<string, ConfigImportMode>, type: string, id: string, defaultMode: ConfigImportMode = CONFIG_PRESET_DEFAULT_IMPORT_MODE) => {
  return modes.get(configPresetPlanKey(type, id)) ?? defaultMode;
};

// The audit event of an import, the wizard or a partial one. The listeners run in a Promise.all: a failing one never fails the import
export const publishConfigPresetImportAction = async (user: AuthUser, contextData: UserConfigPresetImportActionContextData) => {
  try {
    await publishUserAction({ user, event_type: 'command', event_access: 'administration', event_scope: 'import', context_data: contextData });
  } catch (err) {
    logApp.warn('[CONFIG PRESET] The activity event of the import could not be published', { cause: err });
  }
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

// The user who started an import, read again before each item: the rights of the user may have changed since the request.
// The domain functions of the importers check no capability, so BYPASS is checked here; the origin of the request is kept for the audit.
// Throws when the user no longer exists or no longer has BYPASS: the import stops writing.
export const reloadConfigPresetImportUser = async (context: AuthContext, user: AuthUser): Promise<AuthUser> => {
  const cachedUser = await resolveUserByIdFromCache(context, user.id);
  if (!cachedUser) {
    throw FunctionalError('The user who started the import no longer exists');
  }
  if (!isUserHasCapability(cachedUser, BYPASS)) {
    throw FunctionalError('The user who started the import no longer has the right to import');
  }
  return { ...cachedUser, origin: user.origin } as AuthUser;
};
