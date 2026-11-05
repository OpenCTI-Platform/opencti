import type { AttackPatternsMatrixColumns_data$data } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import type { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import type { GraphState } from '../../../../../components/graph/graph.types';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';

export type MatrixPhase = NonNullable<NonNullable<AttackPatternsMatrixColumns_data$data['attackPatternsMatrix']>['attackPatternsOfPhases']>[number];

export interface InvestigationAttackPattern {
  id: string;
  name: string;
}

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

const DEFAULT_KILL_CHAIN = 'mitre-attack';

export const getInvestigationAttackPatterns = (rawObjects: ObjectToParse[]): InvestigationAttackPattern[] => {
  return rawObjects
    .filter((object) => object.entity_type === 'Attack-Pattern')
    .map((object) => ({ id: object.id, name: getMainRepresentative(object) }));
};

export const pickDefaultKillChain = (killChains: string[]): string | undefined => {
  if (killChains.includes(DEFAULT_KILL_CHAIN)) return DEFAULT_KILL_CHAIN;
  return [...killChains].sort((a, b) => a.localeCompare(b))[0];
};

// Techniques and sub-techniques shown in the selected kill chain's skeleton.
export const getKillChainTechniqueIds = (phases: ReadonlyArray<MatrixPhase>, killChain: string): Set<string> => {
  const ids = new Set<string>();
  phases
    .filter((phase) => phase.kill_chain_name === killChain)
    .forEach((phase) => {
      (phase.attackPatterns ?? []).forEach((attackPattern) => {
        ids.add(attackPattern.attack_pattern_id);
        (attackPattern.subAttackPatterns ?? []).forEach((sub) => ids.add(sub.attack_pattern_id));
      });
    });
  return ids;
};

// Revoked attack patterns and those without a phase are never in the skeleton, so they land here.
export const getUnplacedAttackPatterns = (
  investigationAps: InvestigationAttackPattern[],
  placedIds: Set<string>,
): InvestigationAttackPattern[] => {
  return investigationAps.filter(({ id }) => !placedIds.has(id));
};

export const hasActiveGraphFilters = (graphState: GraphState): boolean => {
  return graphState.disabledEntityTypes.length > 0
    || graphState.disabledCreators.length > 0
    || graphState.disabledMarkings.length > 0
    || !!graphState.selectedTimeRangeInterval;
};

export const formatNameList = (names: string[], max: number, t: Translate): string => {
  const shown = names.slice(0, max).join(', ');
  const rest = names.length - max;
  return rest > 0 ? `${shown} ${t('and {count} more', { values: { count: rest } })}` : shown;
};
