import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetExportableType } from '../../generated/graphql';
import { CONFIG_PRESET_FAMILIES } from './configPreset-registry';

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
