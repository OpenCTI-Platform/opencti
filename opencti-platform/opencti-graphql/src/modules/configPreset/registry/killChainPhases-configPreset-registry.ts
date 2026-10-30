import { FilterMode, FilterOperator, KillChainPhasesOrdering, OrderingMode } from '../../../generated/graphql';
import { findAllKillChainPhases, findKillChainPhasePaginated } from '../../../domain/killChainPhase';
import { getKillChainPhaseConfigPresetConfiguration } from '../../killChainPhase/killChainPhase-export';
import { getKillChainPhaseStandardId, importKillChainPhase } from '../../killChainPhase/killChainPhase-import';
import type { BasicStoreEntityKillChainPhase } from '../../killChainPhase/killChainPhase-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, taxonomyGroup, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const KILL_CHAIN_PHASES_FAMILY_ID = 'killChainPhases';

// By kill chain, then by order in the kill chain
const killChainPhasesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    ...(ids ? [{ key: ['standard_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['standard_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: [KillChainPhasesOrdering.KillChainName, KillChainPhasesOrdering.XOpenctiOrder],
    orderMode: OrderingMode.Asc,
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
  };
};

// A phase is identified by its standard id everywhere: derived from its kill chain name and phase name, it is the same on every platform
const toKillChainPhaseItem = (phase: BasicStoreEntityKillChainPhase): ConfigPresetItemDefinition => ({
  id: phase.standard_id,
  label: `${phase.kill_chain_name}: ${phase.phase_name}`,
  translatable: false,
  exporter: async () => getKillChainPhaseConfigPresetConfiguration(phase),
});

const killChainPhasesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode) => {
    const { kill_chain_name: killChainName, phase_name: phaseName } = item.configuration;
    const hasNames = typeof killChainName === 'string' && typeof phaseName === 'string';
    const label = { label: hasNames ? `${killChainName}: ${phaseName}` : item.id, translatable: false };
    // The bundle id of a phase is its standard id: the one of its names
    if (hasNames && getKillChainPhaseStandardId({ kill_chain_name: killChainName.trim(), phase_name: phaseName.trim() }) !== item.id) {
      return { ...label, exists: false, conflict: false, status: 'failed', reason: 'The standard id of the kill chain phase does not match its names' };
    }
    return toComputedItem(label, await importKillChainPhase(context, user, item.configuration, { mode, dryRun: true }));
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importKillChainPhase(context, user, item.configuration, { mode }), computed);
  },
};

// Kill chain phases: paged and searched through the kill chain phase domain. A phase has no copy, an import overwrites.
export const killChainPhasesFamily: ConfigPresetFamilyDefinition = {
  importer: killChainPhasesImporter,
  id: KILL_CHAIN_PHASES_FAMILY_ID,
  label: 'Kill chain phases',
  description: 'Kill chains, their phases and their order',
  group: taxonomyGroup,
  directory: 'taxonomy/kill_chain_phases',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no phase: as a filter value it would match every phase
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findKillChainPhasePaginated(context, user, { first, after, search, ...killChainPhasesArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }: { cursor: string; node: BasicStoreEntityKillChainPhase }) => ({ cursor, node: toKillChainPhaseItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const phases: BasicStoreEntityKillChainPhase[] = await findAllKillChainPhases(context, user, killChainPhasesArgs(ids, excludedIds));
    return phases.map(toKillChainPhaseItem);
  },
};
