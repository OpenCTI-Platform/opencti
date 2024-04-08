import React, { useState } from 'react';
import { graphql, useRefetchableFragment } from 'react-relay';
import Loader from 'src/components/Loader';
import { List, ListItemButton, ListItemIcon, ListItemText, useTheme } from '@mui/material';
import { CheckCircle } from '@mui/icons-material';
import ItemIcon from 'src/components/ItemIcon';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { filter } from 'ramda';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { defaultCommitMutation } from 'src/relay/environment';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import { AddIndividualsThreatActorIndividualLines_data$key } from './__generated__/AddIndividualsThreatActorIndividualLines_data.graphql';

const scoRelationshipAdd = graphql`
  mutation AddIndividualsThreatActorIndividualLinesRelationshipAddMutation(
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

const scoRelationshipDelete = graphql`
  mutation AddIndividualsThreatActorIndividualLinesRelationshipDeleteMutation(
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
  ) {
    ...AddIndividualsThreatActorIndividualLines_data
      @arguments(search: $search, count: $count)
  }
`;

const AddIndividualsThreatActorIndividualLinesFragment = graphql`
  fragment AddIndividualsThreatActorIndividualLines_data on Query
  @refetchable(queryName: "AddIndividualsThreatActorIndividualLinesRefetchQuery")
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
  ) {
    individuals (
      search: $search,
      first: $count,
    ) {
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
  const [data] = useRefetchableFragment(
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

  const updateDelete = (store: RecordSourceSelectorProxy, path: string, rootId: string, deleteId: string) => {
    const node = store.get(rootId);
    const records = node?.getLinkedRecord(path);
    const edges = records?.getLinkedRecords('edges');
    if (!records || !edges) { return; }
    const newEdges = filter(
      (n) => n.getLinkedRecord('node')?.getValue('toId') !== deleteId,
      edges,
    );
    records.setLinkedRecords(newEdges, 'edges');
  };

  const handleToggle = (toId: string) => {
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
        updater: (store) => updateDelete(
          store,
          'stixCoreRelationships',
          threatActorIndividual.id,
          toId,
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

  if (data.individuals?.edges) {
    const availableTargets = data.individuals.edges;
    return (
      <List>
        {availableTargets.map((node, i) => {
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
  }
  return (<Loader />);
};

export default AddIndividualsThreatActorIndividualLines;
