import React, { FunctionComponent, useState } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import AttackPatternsMatrix from '../../techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import { SecurityCoverageAttackPatternsMatrix_securityCoverage$data } from './__generated__/SecurityCoverageAttackPatternsMatrix_securityCoverage.graphql';
import StixCoreRelationshipCreationFromEntity, { TargetEntity } from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';

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
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>([]);

  const attackPatterns = ((securityCoverage.attackPatterns?.edges ?? [])
    .map((edge) => edge.node)
    .filter((node) => node !== null && node !== undefined)
    .map((node) => node.to)) as unknown as Parameters<typeof AttackPatternsMatrix>[0]['attackPatterns'];

  const attackPatternsCoverageMap = new Map<string, ReadonlyArray<{ readonly coverage_name: string; readonly coverage_score: number; }>>();
  (securityCoverage.attackPatterns?.edges ?? []).forEach((edge) => {
    const { node } = edge;
    if (node && node.to?.id) {
      attackPatternsCoverageMap.set(node.to.id, node.coverage_information || []);
    }
  });

  const handleAdd = (entity: TargetEntity) => {
    setTargetEntities([entity]);
  };

  const handleOnCreate = () => {
    // Refresh the component to show the new relationship
    relay.refetch({ id: securityCoverage.id });
    setTargetEntities([]);
  };

  const paginationOptions = {
    count: 25,
    orderBy: 'created_at',
    orderMode: 'asc',
    filters: {
      mode: 'and',
      filters: [],
      filterGroups: [],
    },
  };

  return (
    <>
      <AttackPatternsMatrix
        attackPatterns={attackPatterns}
        searchTerm={searchTerm}
        entityType="Security-Coverage"
        handleAdd={handleAdd}
        selectedKillChain={selectedKillChain}
        attackPatternIdsToOverlap={[]}
        isModeOnlyActive={false}
        inPaper={true}
        isCoverage={true}
        coverageMap={attackPatternsCoverageMap}
        entityId={securityCoverage.id}
      />
      <StixCoreRelationshipCreationFromEntity
        entityId={securityCoverage.id}
        targetEntities={targetEntities}
        allowedRelationshipTypes={['has-covered']}
        targetStixDomainObjectTypes={['Attack-Pattern']}
        paginationOptions={paginationOptions}
        paddingRight={220}
        onCreate={handleOnCreate}
        isCoverage={true}
        openExports={true}
      />
    </>
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
              coverage_information {
                coverage_name
                coverage_score
              }
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
