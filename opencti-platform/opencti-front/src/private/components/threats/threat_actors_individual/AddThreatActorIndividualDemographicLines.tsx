import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { List, ListItemButton, ListItemIcon, ListItemText, useTheme } from '@mui/material';
import { CheckCircle } from '@mui/icons-material';
import ItemIcon from 'src/components/ItemIcon';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import {
  AddThreatActorIndividualDemographicLines_data$key,
} from '@components/threats/threat_actors_individual/__generated__/AddThreatActorIndividualDemographicLines_data.graphql';
import { ThreatActorIndividual_ThreatActorIndividual$data } from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import { deleteNodeFromEdge } from '../../../../utils/store';

export const scoRelationshipAdd = graphql`
  mutation AddThreatActorIndividualDemographicLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      from {
        ... on ThreatActorIndividual {
          id
          stixCoreRelationships {
            edges {
              node {
                id
                fromId
                toId
                entity_type
                relationship_type
              }
            }
          }
        }
      }
      to {
        ... on Country {
          id
        }
      }
    }
  }
`;

export const scoRelationshipDelete = graphql`
  mutation AddThreatActorIndividualDemographicLinesRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId,
      toId: $toId,
      relationship_type: $relationship_type
    )
  }
`;

export const addIndividualsThreatActorIndividualLinesQuery = graphql`
  query AddThreatActorIndividualDemographicLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddThreatActorIndividualDemographicLines_data
    @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddThreatActorIndividualDemographicLinesFragment = graphql`
  fragment AddThreatActorIndividualDemographicLines_data on Query
  @refetchable(queryName: "AddThreatActorIndividualDemographicLinesRefetchQuery")
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 },
    cursor: { type: "ID" },
  ) {
    countries (
      search: $search,
      first: $count,
      after: $cursor,
    ) @connection(key: "Pagination_countries") {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const AddThreatActorIndividualDemographicLine = ({
  id,
  name,
  currentTargets,
  handleClick,
}: {
  id: string,
  name: string,
  currentTargets: string[],
  handleClick: () => void,
}) => {
  const theme = useTheme();
  return (
    <ListItemButton
      divider={true}
      onClick={handleClick}
    >
      <ListItemIcon>
        {currentTargets.includes(id)
          ? <CheckCircle style={{ color: theme.palette.primary.main }} />
          : <ItemIcon type='Country' />
        }
      </ListItemIcon>
      <ListItemText
        primary={name}
      />
    </ListItemButton>
  );
};

const AddThreatActorIndividualDemographicLines = ({
  threatActorIndividual,
  fragmentKey,
  relType,
}: {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data,
  fragmentKey: AddThreatActorIndividualDemographicLines_data$key,
  relType: string,
}) => {
  const data = useFragment(
    AddThreatActorIndividualDemographicLinesFragment,
    fragmentKey,
  );
  const [commitRelationAdd] = useApiMutation(scoRelationshipAdd);
  const [commitRelationDelete] = useApiMutation(scoRelationshipDelete);

  const initialTargets = (threatActorIndividual
    .stixCoreRelationships?.edges
    .filter(({ node }) => node.relationship_type === relType)
    ?? []).map(({ node }) => node.to?.id ?? '');

  const [currentTargets, setCurrentTargets] = useState<string[]>(initialTargets);

  const handleToggle = (toId: string) => {
    const stixCoreRelationshipId = threatActorIndividual
      .stixCoreRelationships?.edges
      .find(({ node }) => node.to?.id === toId && node.relationship_type === relType)?.node.id;
    const isSelected = currentTargets.includes(toId);
    const input = {
      fromId: threatActorIndividual.id,
      toId,
      relationship_type: relType,
    };
    if (isSelected) {
      commitRelationDelete({
        variables: { ...input },
        updater: (store) => deleteNodeFromEdge(
          store,
          'stixCoreRelationships',
          threatActorIndividual.id,
          stixCoreRelationshipId,
        ),
        onCompleted: () => {
          setCurrentTargets(currentTargets.filter((id) => id !== toId));
        },
      });
    } else {
      commitRelationAdd({
        variables: { input },
        onCompleted: () => {
          setCurrentTargets([...currentTargets, toId]);
        },
      });
    }
  };

  const availableTargets = data.countries?.edges;
  return (
    <List>
      {availableTargets?.map((node, i) => {
        if (node) {
          return (
            <AddThreatActorIndividualDemographicLine
              key={node.node.id}
              id={node.node.id}
              name={node.node.name}
              currentTargets={currentTargets}
              handleClick={() => handleToggle(node.node.id)}
            />
          );
        }
        return <div key={i} />;
      })}
    </List>
  );
};

export default AddThreatActorIndividualDemographicLines;
