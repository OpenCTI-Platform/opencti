import type { AuthContext, AuthUser } from '../../../types/user';
import { buildPaginationFromEdges } from '../../../database/utils';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetListItemsArgs } from '../configPreset-types';

// Export groups of the spec table; a group is added with its first category
export const platformSettingsGroup = { id: 'platformSettings', label: 'Platform settings' };
export const dataModelGroup = { id: 'dataModel', label: 'Data model' };

// The search does not apply to static items: their label is a source string the UI translates,
// so a match on it would not be the text the user sees. They are always listed.
export const matchesListArgs = (item: ConfigPresetItemDefinition, { ids, excludedIds }: ConfigPresetListItemsArgs) => {
  return (!ids || ids.includes(item.id)) && !(excludedIds ?? []).includes(item.id);
};

// A connection of the edges of a page, whose next page is known by the caller (the cursor of a static item is its id)
export const buildConfigPresetConnection = <T>(
  { first, after }: ConfigPresetListItemsArgs,
  edges: { node: T; cursor: string }[],
  globalCount: number,
  hasNextPage: boolean,
) => {
  const connection = buildPaginationFromEdges(first ?? undefined, after, edges, globalCount);
  return { ...connection, pageInfo: { ...connection.pageInfo, hasNextPage } };
};

// A category of static items (one for a singleton), paged on their ids
export const staticFamily = (
  family: Pick<ConfigPresetFamilyDefinition, 'id' | 'label' | 'description' | 'group' | 'directory'>,
  getItems: (context: AuthContext, user: AuthUser) => Promise<ConfigPresetItemDefinition[]>,
): ConfigPresetFamilyDefinition => ({
  ...family,
  listItems: async (context, user, args) => {
    const items = (await getItems(context, user)).filter((item) => matchesListArgs(item, args));
    const start = args.after ? items.findIndex((item) => item.id === args.after) + 1 : 0;
    const page = args.first ? items.slice(start, start + args.first) : items.slice(start);
    return buildConfigPresetConnection(args, page.map((node) => ({ node, cursor: node.id })), items.length, start + page.length < items.length);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    return (await getItems(context, user)).filter((item) => matchesListArgs(item, { ids, excludedIds }));
  },
});
