import React, { FunctionComponent, useMemo } from 'react';
import { createFragmentContainer, graphql, PreloadedQuery } from 'react-relay';
import AttackPatternsMatrix from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { SecurityCoverageAttackPatternsMatrix_securityCoverage$data } from './__generated__/SecurityCoverageAttackPatternsMatrix_securityCoverage.graphql';
import { AttackPatternsMatrixQuery } from '../../techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import { buildAverageCoverageMap } from './securityCoverageAggregation';

interface SecurityCoverageAttackPatternsMatrixProps {
  securityCoverage: SecurityCoverageAttackPatternsMatrix_securityCoverage$data;
  searchTerm: string;
  selectedKillChain: string;
  isModeOnlyActive: boolean;
  matrixQueryRef?: PreloadedQuery<AttackPatternsMatrixQuery>;
}

const SecurityCoverageAttackPatternsMatrixComponent: FunctionComponent<SecurityCoverageAttackPatternsMatrixProps> = ({
  securityCoverage,
  searchTerm,
  selectedKillChain,
  isModeOnlyActive,
  matrixQueryRef,
}) => {
  const coveredEntities = securityCoverage.attackPatterns?.entities ?? [];
  const attackPatterns = useMemo(() => {
    const seenAttackPatternIds = new Set<string>();
    return (coveredEntities
      .filter((node) => {
        const id = node?.to?.id;
        if (!id || seenAttackPatternIds.has(id)) return false;
        seenAttackPatternIds.add(id);
        return true;
      })
      .map((node) => node.to)) as unknown as Parameters<typeof AttackPatternsMatrix>[0]['attackPatterns'];
  }, [coveredEntities]);

  const attackPatternsCoverageMap = useMemo(
    () => buildAverageCoverageMap(coveredEntities),
    [coveredEntities],
  );

  return (
    <AttackPatternsMatrix
      attackPatterns={attackPatterns}
      searchTerm={searchTerm}
      entityType="Security-Coverage"
      selectedKillChain={selectedKillChain}
      attackPatternIdsToOverlap={[]}
      isModeOnlyActive={isModeOnlyActive}
      inPaper={true}
      isCoverage={true}
      coverageMap={attackPatternsCoverageMap}
      entityId={securityCoverage.id}
      queryRef={matrixQueryRef}
    />
  );
};

const SecurityCoverageAttackPatternsMatrix = createFragmentContainer(
  SecurityCoverageAttackPatternsMatrixComponent,
  {
    securityCoverage: graphql`
      fragment SecurityCoverageAttackPatternsMatrix_securityCoverage on SecurityCoverage 
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 5000 }
        filters: { type: "FilterGroup" }
      ) {
        id
        attackPatterns: coveredAttackPatterns(
          search: $search
          first: $count
          filters: $filters
        ) {
          entities {
            coverage_information {
              coverage_name
              coverage_score
            }
            to {
              id
              entity_type
              parent_types
              name
              description
              x_mitre_id
              isSubAttackPattern
              x_mitre_platforms
              x_mitre_permissions_required
              x_mitre_detection
              killChainPhases {
                id
                phase_name
                x_opencti_order
              }
            }
          }
        }
      }
    `,
  },
);

export default SecurityCoverageAttackPatternsMatrix;
