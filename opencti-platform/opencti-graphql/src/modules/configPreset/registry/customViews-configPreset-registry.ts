import { CustomViewsOrdering } from '../../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection } from '../../../database/middleware-loader';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { exportCustomViewToBundle } from '../../customView/customView-export';
import { importCustomView } from '../../customView/customView-import';
import { type BasicStoreEntityCustomView, ENTITY_TYPE_CUSTOM_VIEW } from '../../customView/customView-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, customizationGroup, plannedNamesOf, standardIdListArgs, toAppliedItem, toComputedItem } from './common-configPreset-registry';

export const CUSTOM_VIEWS_FAMILY_ID = 'customViews';

const customViewsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({
  orderBy: CustomViewsOrdering.Name,
  ...standardIdListArgs(ids, excludedIds),
});

// What an item is called: the same name can be the one of the views of two entity types, so the type is said too
const customViewLabel = (name: unknown, targetEntityType: unknown, fallback: string) => {
  if (typeof name !== 'string' || !name.trim()) {
    return fallback;
  }
  return typeof targetEntityType === 'string' && targetEntityType.trim() ? `${name.trim()} (${targetEntityType.trim()})` : name.trim();
};

// The standard id of a custom view is random: it is the same in the bundle and on the platform it comes from, not on another one
const toCustomViewItem = (customView: BasicStoreEntityCustomView): ConfigPresetItemDefinition => ({
  id: customView.standard_id,
  label: customViewLabel(customView.name, customView.target_entity_type, customView.standard_id),
  translatable: false,
  exporter: async (context, user) => exportCustomViewToBundle(context, user, customView),
});

const customViewsImporter: ConfigPresetImporter = {
  // The bundle id cannot be checked against the content: the view is matched by its entity type and its name, not by its id
  compute: async (context, user, item, plan, mode) => {
    const { name, target_entity_type: targetEntityType } = item.configuration;
    const label = { label: customViewLabel(name, targetEntityType, item.id), translatable: false };
    const result = await importCustomView(context, user, item.configuration, { mode, dryRun: true, reservedNames: plannedNamesOf(plan, CUSTOM_VIEWS_FAMILY_ID) });
    return toComputedItem(label, result);
  },
  apply: async (context, user, item, computed, mode) => toAppliedItem(await importCustomView(context, user, item.configuration, { mode }), computed),
};

// Custom views of every entity type, paged and searched through the loaders. An import matches a view by its entity type and its name:
// it overwrites it, or adds a copy of it under a free name. A view is imported neither enabled nor the default of its entity type.
export const customViewsFamily: ConfigPresetFamilyDefinition = {
  importer: customViewsImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: CUSTOM_VIEWS_FAMILY_ID,
  label: 'Custom views',
  description: 'Custom views of the entity types and their widgets',
  group: customizationGroup,
  directory: 'customization/custom_views',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no view: as a filter value it would match every view
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await pageEntitiesConnection<BasicStoreEntityCustomView>(context, user, [ENTITY_TYPE_CUSTOM_VIEW], { first, after, search, ...customViewsArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toCustomViewItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const customViews = await fullEntitiesList<BasicStoreEntityCustomView>(context, user, [ENTITY_TYPE_CUSTOM_VIEW], customViewsArgs(ids, excludedIds));
    return customViews.map(toCustomViewItem);
  },
};
