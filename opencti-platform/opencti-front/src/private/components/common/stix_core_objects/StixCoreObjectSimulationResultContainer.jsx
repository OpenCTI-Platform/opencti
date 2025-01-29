import React, { useState } from 'react';
import { graphql } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import StixCoreObjectSimulationResult from './StixCoreObjectSimulationResult';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const StixCoreObjectSimulationResultAttackPatternsForContainersQuery = graphql`
  query StixCoreObjectSimulationResultContainerAttackPatternsForContainersQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      ... on Container {
        objects (types: ["Attack-Pattern"]){
          edges {
            types
            node {
              ... on AttackPattern {
                id
              }
            }
          }
        }
      }
    }
  }
`;

const stixCoreObjectSimulationResultAttackPatternsForThreatsQuery = graphql`
  query StixCoreObjectSimulationResultContainerAttackPatternsForThreatsQuery($id: Any!) {
    stixCoreRelationships(filters: {
      mode: and,
      filters: [
        {
          key: "relationship_type",
          values: ["uses"],
        },
        {
          key: "fromOrToId",
          values: [$id],
        },
        {
          key: "elementWithTargetTypes",
          values: ["Attack-Pattern"],
        }
      ],
      filterGroups: [

      ],
    }) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const StixCoreObjectSimulationResultContainer = ({ id, type }) => {
  const [simulationType, setSimulationType] = useState('technical');
  // Determine the query based on the type
  let attackPatternsQuery;
  if (type === 'container') {
    attackPatternsQuery = StixCoreObjectSimulationResultAttackPatternsForContainersQuery;
  } else if (type === 'threat') {
    attackPatternsQuery = stixCoreObjectSimulationResultAttackPatternsForThreatsQuery;
  } else {
    throw new Error('Type of the simulation should be container or threat');
  }

  // Fetch the attackPatterns using the selected query
  const attackPatternsQueryRef = useQueryLoading(attackPatternsQuery, { id });

  return (
    <>
      {attackPatternsQueryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
          <StixCoreObjectSimulationResult
            id={id}
            query={attackPatternsQuery}
            queryRef={attackPatternsQueryRef}
            type={type}
            simulationType={simulationType}
            setSimulationType={setSimulationType}
          />
        </React.Suspense>
      )}
    </>
  );
};
export default StixCoreObjectSimulationResultContainer;
