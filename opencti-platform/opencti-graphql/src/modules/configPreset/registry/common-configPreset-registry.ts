import type { AuthContext, AuthUser } from '../../../types/user';
import { buildPaginationFromEdges } from '../../../database/utils';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetListItemsArgs } from '../configPreset-types';

// Export groups of the spec table; a group is added with its first category
export const platformSettingsGroup = { id: 'platformSettings', label: 'Platform settings' };
export const dataModelGroup = { id: 'dataModel', label: 'Data model' };

export const matchesListArgs = (item: ConfigPresetItemDefinition, { ids, excludedIds, search }: ConfigPresetListItemsArgs) => {
  return (!ids || ids.includes(item.id))
    && !(excludedIds ?? []).includes(item.id)
    && (!search || item.label.toLowerCase().includes(search.toLowerCase()));
};

// A category of static items (one for a singleton), on a single page
export const staticFamily = (
  family: Pick<ConfigPresetFamilyDefinition, 'id' | 'label' | 'description' | 'group' | 'directory'>,
  getItems: (context: AuthContext, user: AuthUser) => Promise<ConfigPresetItemDefinition[]>,
): ConfigPresetFamilyDefinition => ({
  ...family,
  listItems: async (context, user, args) => {
    const items = (await getItems(context, user)).filter((item) => matchesListArgs(item, args));
    return buildPaginationFromEdges(undefined, null, items.map((node) => ({ node, cursor: node.id })), items.length);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    return (await getItems(context, user)).filter((item) => matchesListArgs(item, { ids, excludedIds }));
  },
});
