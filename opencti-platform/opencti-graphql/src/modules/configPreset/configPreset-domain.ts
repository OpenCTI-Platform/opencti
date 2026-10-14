import { CONFIG_PRESET_FEATURE_FLAG } from '../../config/conf';
import { enforceEnableFeatureFlag } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetExportableType } from '../../generated/graphql';
import { CONFIG_PRESET_FAMILIES } from './configPreset-registry';

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
