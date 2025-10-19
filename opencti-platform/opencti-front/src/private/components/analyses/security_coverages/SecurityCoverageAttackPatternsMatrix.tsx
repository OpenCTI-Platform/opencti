import React, { FunctionComponent } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import AttackPatternsMatrix from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { SecurityCoverageAttackPatternsMatrix_securityCoverage$data } from './__generated__/SecurityCoverageAttackPatternsMatrix_securityCoverage.graphql';
import { commitMutation } from '../../../../relay/environment';
import { TargetEntity } from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

const addRelationshipMutation = graphql`
  mutation SecurityCoverageAttackPatternsMatrixAddRelationMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      id
      from {
        ... on SecurityCoverage {
          id
          attackPatterns: stixCoreRelationships(
            relationship_type: "has-covered"
            toTypes: ["Attack-Pattern"]
          ) {
            edges {
              node {
                id
                to {
                  ... on AttackPattern {
                    id
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

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
  relay,
}) => {
  const attackPatterns = (securityCoverage.attackPatterns?.edges ?? [])
    .map((edge) => edge.node)
    .filter((node) => node !== null && node !== undefined)
    .map((node) => node.to) as any;

  const handleAdd = (entity: TargetEntity) => {
    commitMutation({
      mutation: addRelationshipMutation,
      variables: {
        input: {
          fromId: securityCoverage.id,
          toId: entity.id,
          relationship_type: 'has-covered',
        },
      },
      updater: (_store: RecordSourceSelectorProxy) => {
        // Refresh the component to show the new relationship
        relay.refetch({ id: securityCoverage.id });
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <AttackPatternsMatrix
      attackPatterns={attackPatterns}
      searchTerm={searchTerm}
      entityType="Security-Coverage"
      handleAdd={handleAdd}
      selectedKillChain={selectedKillChain}
      attackPatternIdsToOverlap={[]}
      isModeOnlyActive={false}
    />
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
