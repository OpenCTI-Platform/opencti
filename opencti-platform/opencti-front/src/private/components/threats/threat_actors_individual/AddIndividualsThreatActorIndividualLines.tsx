import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { List, ListItemButton, ListItemIcon, ListItemText, useTheme } from '@mui/material';
import { CheckCircle } from '@mui/icons-material';
import ItemIcon from 'src/components/ItemIcon';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { defaultCommitMutation } from 'src/relay/environment';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import { AddIndividualsThreatActorIndividualLines_data$key } from './__generated__/AddIndividualsThreatActorIndividualLines_data.graphql';
import { deleteNodeFromEdge } from '../../../../utils/store';

export const scoRelationshipAdd = graphql`
  mutation AddIndividualsThreatActorIndividualLinesRelationAddMutation(
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
        ... on Individual {
          id
        }
      }
    }
  }
`;

export const scoRelationshipDelete = graphql`
  mutation AddIndividualsThreatActorIndividualLinesRelationDeleteMutation(
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
  query AddIndividualsThreatActorIndividualLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddIndividualsThreatActorIndividualLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddIndividualsThreatActorIndividualLinesFragment = graphql`
  fragment AddIndividualsThreatActorIndividualLines_data on Query
  @refetchable(queryName: "AddIndividualsThreatActorIndividualLinesRefetchQuery")
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 },
    cursor: { type: "ID" },
  ) {
    individuals (
      search: $search,
      first: $count,
      after: $cursor,
    ) @connection(key: "Pagination_individuals") {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const AddIndividualsThreatActorIndividualLine = ({
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
          : <ItemIcon type='Individual' />
        }
      </ListItemIcon>
      <ListItemText
        primary={name}
      />
    </ListItemButton>
  );
};

const AddIndividualsThreatActorIndividualLines = ({
  threatActorIndividual,
  fragmentKey,
}: {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
  fragmentKey: AddIndividualsThreatActorIndividualLines_data$key,
}) => {
  const data = useFragment(
    AddIndividualsThreatActorIndividualLinesFragment,
    fragmentKey,
  );
  const [commitRelationAdd] = useApiMutation(scoRelationshipAdd);
  const [commitRelationDelete] = useApiMutation(scoRelationshipDelete);

  const initialTargets = (threatActorIndividual
    .stixCoreRelationships?.edges
    .filter(({ node }) => node.relationship_type === 'impersonates')
    ?? []).map(({ node }) => node.to?.id ?? '');

  const [currentTargets, setCurrentTargets] = useState<string[]>(initialTargets);

  const handleToggle = (toId: string) => {
    const stixCoreRelationshipId = threatActorIndividual
      .stixCoreRelationships?.edges
      .find(({ node }) => node.to?.id === toId && node.relationship_type === 'impersonates')?.node.id;
    const isSelected = currentTargets.includes(toId);
    const input = {
      fromId: threatActorIndividual.id,
      toId,
      relationship_type: 'impersonates',
    };
    if (isSelected) {
      commitRelationDelete({
        ...defaultCommitMutation,
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
        ...defaultCommitMutation,
        variables: { input },
        onCompleted: () => {
          setCurrentTargets([...currentTargets, toId]);
        },
      });
    }
  };

  const availableTargets = data.individuals?.edges;
  return (
    <List>
      {availableTargets?.map((node, i) => {
        if (node) {
          return (
            <AddIndividualsThreatActorIndividualLine
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

export default AddIndividualsThreatActorIndividualLines;
