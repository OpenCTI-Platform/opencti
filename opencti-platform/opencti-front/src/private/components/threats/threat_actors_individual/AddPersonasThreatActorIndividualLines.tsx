import React, { useState } from 'react';
import { graphql, useRefetchableFragment } from 'react-relay';
import Loader from 'src/components/Loader';
import { List, ListItemButton, ListItemIcon, ListItemText, useTheme } from '@mui/material';
import ItemIcon from 'src/components/ItemIcon';
import { CheckCircle } from '@mui/icons-material';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { defaultCommitMutation } from 'src/relay/environment';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { filter } from 'ramda';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import { AddPersonasThreatActorIndividualLines_data$key } from './__generated__/AddPersonasThreatActorIndividualLines_data.graphql';

const scoRelationshipAdd = graphql`
  mutation AddPersonasThreatActorIndividualLinesRelationshipAddMutation(
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
  mutation AddPersonasThreatActorIndividualLinesRelationshipDeleteMutation(
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
export const addPersonasThreatActorIndividualLinesQuery = graphql`
  query AddPersonasThreatActorIndividualLinesQuery(
    $search: String
    $count: Int!
  ) {
    ...AddPersonasThreatActorIndividualLines_data
      @arguments(search: $search, count: $count)
  }
`;

const AddPersonasThreatActorIndividualLinesFragment = graphql`
  fragment AddPersonasThreatActorIndividualLines_data on Query
  @refetchable(queryName: "AddPersonasThreatActorIndividualLinesRefetchQuery")
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
  ) {
    stixCyberObservables(
      search: $search,
      first: $count,
      types: ["Persona"],
    ) {
      edges {
        node {
          id
          ... on Persona {
            persona_name
            persona_type
          }
        }
      }
    }
  }
`;

const AddPersonasThreatActorIndividualLine = ({
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

const AddPersonasThreatActorIndividualLines = ({
  threatActorIndividual,
  fragmentKey,
}: {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
  fragmentKey: AddPersonasThreatActorIndividualLines_data$key,
}) => {
  const [data] = useRefetchableFragment(
    AddPersonasThreatActorIndividualLinesFragment,
    fragmentKey,
  );

  const [commitRelationAdd] = useApiMutation(scoRelationshipAdd);
  const [commitRelationDelete] = useApiMutation(scoRelationshipDelete);

  const initialTargets = (threatActorIndividual
    .stixCoreRelationships?.edges
    .filter(({ node }) => node.relationship_type === 'known-as')
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
      relationship_type: 'known-as',
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

  if (data.stixCyberObservables) {
    return (
      <List>
        {data.stixCyberObservables.edges.map((node, i) => {
          if (node) {
            return (
              <AddPersonasThreatActorIndividualLine
                key={node.node.id}
                id={node.node.id}
                name={node.node.persona_name ? node.node.persona_name : ''}
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

export default AddPersonasThreatActorIndividualLines;
