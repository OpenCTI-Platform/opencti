import { ExclusionListOrdering, FilterMode, FilterOperator, OrderingMode } from '../../../generated/graphql';
import { FunctionalError } from '../../../config/errors';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { exportExclusionList } from '../../exclusionList/exclusionList-export';
import { readExclusionListFile } from '../../exclusionList/exclusionList-file';
import { findExclusionListPaginated } from '../../exclusionList/exclusionList-domain';
import { importExclusionList } from '../../exclusionList/exclusionList-import';
import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST } from '../../exclusionList/exclusionList-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, customizationGroup, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const EXCLUSION_LISTS_FAMILY_ID = 'exclusionLists';

const exclusionListsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    ...(ids ? [{ key: ['standard_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['standard_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: ExclusionListOrdering.Name,
    orderMode: OrderingMode.Asc,
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
  };
};

// The bundle id of an exclusion list is its standard id, which is random: the same list has another one on every platform.
// It only tells the items of a bundle apart: a list is found on the platform that imports it by its name.
// The values of the list are its file, written as it is stored next to the JSON of the list: the attachment of the item.
const toExclusionListItem = (list: BasicStoreEntityExclusionList): ConfigPresetItemDefinition => ({
  id: list.standard_id,
  label: list.name,
  translatable: false,
  exporter: async () => exportExclusionList(list),
  attachment: {
    name: `${list.standard_id}.txt`,
    read: async () => {
      const content = await readExclusionListFile(list);
      if (!content) {
        throw FunctionalError('The file of the values of an exclusion list is missing from the storage or is not its own', { id: list.internal_id, name: list.name });
      }
      return content;
    },
  },
});

const exclusionListsImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode) => {
    const { name } = item.configuration;
    const label = { label: typeof name === 'string' ? name.trim() : item.id, translatable: false };
    plan.exclusionListNames ??= new Set();
    return toComputedItem(label, await importExclusionList(context, user, item.configuration, item.attachment, { mode, dryRun: true, reservedNames: plan.exclusionListNames }));
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importExclusionList(context, user, item.configuration, item.attachment, { mode }), computed);
  },
};

// Exclusion lists with their values, paged and searched through the exclusion list domain. An import overwrites, or adds a copy under a free name.
export const exclusionListsFamily: ConfigPresetFamilyDefinition = {
  importer: exclusionListsImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: EXCLUSION_LISTS_FAMILY_ID,
  label: 'Exclusion lists',
  description: 'Exclusion lists and their values',
  group: customizationGroup,
  directory: 'customization/exclusion_lists',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no list: as a filter value it would match every list
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findExclusionListPaginated(context, user, { first, after, search, ...exclusionListsArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }: { cursor: string; node: BasicStoreEntityExclusionList }) => ({ cursor, node: toExclusionListItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const lists = await fullEntitiesList<BasicStoreEntityExclusionList>(context, user, [ENTITY_TYPE_EXCLUSION_LIST], exclusionListsArgs(ids, excludedIds));
    return lists.map(toExclusionListItem);
  },
};
