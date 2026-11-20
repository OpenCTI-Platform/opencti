import type { AttackPatternsMatrixColumns_data$data } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import type { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import { getMatrixConfig } from '../../../techniques/attack_patterns/attack_patterns_matrix/attackPatternsMatrixConfig';

export type MatrixPhase = NonNullable<NonNullable<AttackPatternsMatrixColumns_data$data['attackPatternsMatrix']>['attackPatternsOfPhases']>[number];

export interface InvestigationAttackPattern {
  id: string;
  name: string;
  x_mitre_id?: string | null;
}

const DEFAULT_KILL_CHAIN = 'mitre-attack';

export const getInvestigationAttackPatterns = (rawObjects: ObjectToParse[]): InvestigationAttackPattern[] => {
  return rawObjects
    .filter((object) => object.entity_type === 'Attack-Pattern')
    .map((object) => {
      const { x_mitre_id } = object as ObjectToParse & { x_mitre_id?: string | null };
      return {
        id: object.id,
        // getMainRepresentative prefixes the T-code to the name; the label adds it once, so the name is read without it.
        name: getMainRepresentative({ ...object, x_mitre_id: undefined }),
        // The query fetches the T-code, but ObjectToParse does not declare it.
        x_mitre_id,
      };
    });
};

// Same label as the matrix cells: the T-code before the name, the name alone without one.
export const formatAttackPatternLabel = (ap: InvestigationAttackPattern): string => {
  return getMatrixConfig('investigation', false).formatLabel(ap);
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
