import { MarkingDefinitionsOrdering } from '../../../generated/graphql';
import { findAllMarkings, findMarkingsPaginated } from '../../../domain/markingDefinition';
import { type BasicStoreEntityMarking, exportMarking } from '../../markingDefinition/marking-export';
import { importMarking, markingStandardId } from '../../markingDefinition/marking-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, MARKINGS_FAMILY_ID, securityAccessGroup, standardIdListArgs, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

// Built-in markings are exported like any other: their color and order can be customized, and a deleted one is re-created with its fixed id
const markingsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({ orderBy: MarkingDefinitionsOrdering.Definition, ...standardIdListArgs(ids, excludedIds) });

const toMarkingItem = (marking: BasicStoreEntityMarking): ConfigPresetItemDefinition => ({
  id: marking.standard_id,
  label: marking.definition,
  translatable: false,
  exporter: async () => exportMarking(marking),
});

const markingsImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const { definition_type: definitionType, definition } = item.configuration;
    const label = { label: typeof definition === 'string' && definition.trim() ? definition : item.id, translatable: false };
    if (typeof definitionType === 'string' && typeof definition === 'string' && definitionType.trim() && definition.trim()
      && markingStandardId(definitionType, definition) !== item.id) {
      return { ...label, exists: false, conflict: false, status: 'failed', reason: 'The standard id of the marking does not match its definition' };
    }
    const result = await importMarking(context, user, item.configuration, { mode, dryRun: true });
    if (result.status === 'created') {
      plan.created.add(configPresetPlanKey(MARKINGS_FAMILY_ID, item.id));
    }
    const order = result.configuration?.x_opencti_order;
    if (result.configuration && (result.status === 'created' || (result.status === 'overwritten' && order !== null && order !== undefined))) {
      const { definition_type: plannedType, definition: plannedDefinition } = result.configuration;
      plan.plannedMarkings?.set(item.id, { definition_type: plannedType, definition: plannedDefinition, x_opencti_order: order ?? 0 });
    }
    return toComputedItem(label, result);
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importMarking(context, user, item.configuration, { mode }), computed);
  },
};

export const markingsFamily: ConfigPresetFamilyDefinition = {
  importer: markingsImporter,
  id: MARKINGS_FAMILY_ID,
  label: 'Markings',
  description: 'Marking definitions, their colors and orders',
  group: securityAccessGroup,
  directory: 'security_access/markings',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findMarkingsPaginated(context, user, { first, after, search, ...markingsArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }: { cursor: string; node: BasicStoreEntityMarking }) => ({ cursor, node: toMarkingItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    return ((await findAllMarkings(context, user, markingsArgs(ids, excludedIds))) as BasicStoreEntityMarking[]).map(toMarkingItem);
  },
};
