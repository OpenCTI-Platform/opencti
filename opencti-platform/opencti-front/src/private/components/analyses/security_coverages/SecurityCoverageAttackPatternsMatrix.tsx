import React, { FunctionComponent } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import AttackPatternsMatrix from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { SecurityCoverageAttackPatternsMatrix_securityCoverage$data } from './__generated__/SecurityCoverageAttackPatternsMatrix_securityCoverage.graphql';

interface SecurityCoverageAttackPatternsMatrixProps {
  securityCoverage: SecurityCoverageAttackPatternsMatrix_securityCoverage$data;
  searchTerm: string;
  selectedKillChain: string;
  relay: RelayRefetchProp;
}

const SecurityCoverageAttackPatternsMatrixComponent: FunctionComponent<SecurityCoverageAttackPatternsMatrixProps> = ({
  securityCoverage,
  searchTerm,
  selectedKillChain,
}) => {
  const attackPatterns = (securityCoverage.attackPatterns?.edges ?? [])
    .map((edge) => edge.node)
    .filter((node) => node !== null && node !== undefined)
    .map((node) => node.to);

  return (
    <div style={{ marginTop: 20, marginBottom: 20 }}>
      <AttackPatternsMatrix
        attackPatterns={attackPatterns}
        searchTerm={searchTerm}
        entityType="Security-Coverage"
        handleAdd={() => {}} // No add functionality for covered patterns
        selectedKillChain={selectedKillChain}
        attackPatternIdsToOverlap={[]}
        isModeOnlyActive={false}
      />
    </div>
  );
};

const SecurityCoverageAttackPatternsMatrix = createRefetchContainer(
  SecurityCoverageAttackPatternsMatrixComponent,
  {
    securityCoverage: graphql`
      fragment SecurityCoverageAttackPatternsMatrix_securityCoverage on SecurityCoverage 
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 200 }
        cursor: { type: "ID" }
      ) {
        id
        attackPatterns: stixCoreRelationships(
          relationship_type: "has-covered"
          toTypes: ["Attack-Pattern"]
          search: $search
          first: $count
          after: $cursor
        ) @connection(key: "Pagination_attackPatterns") {
          edges {
            node {
              id
              to {
                ... on AttackPattern {
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
        }
      }
    `,
  },
  graphql`
    query SecurityCoverageAttackPatternsMatrixRefetchQuery(
      $id: String!
      $search: String
      $count: Int
      $cursor: ID
    ) {
      securityCoverage(id: $id) {
        ...SecurityCoverageAttackPatternsMatrix_securityCoverage
          @arguments(search: $search, count: $count, cursor: $cursor)
      }
    }
  `,
);

export default SecurityCoverageAttackPatternsMatrix;
