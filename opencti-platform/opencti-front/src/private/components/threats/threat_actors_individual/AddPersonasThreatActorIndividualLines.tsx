import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, useRefetchableFragment } from 'react-relay';
import Loader from 'src/components/Loader';
import { List, ListItemButton, ListItemIcon, ListItemText, useTheme } from '@mui/material';
import ItemIcon from 'src/components/ItemIcon';
import { CheckCircle } from '@mui/icons-material';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { defaultCommitMutation } from 'src/relay/environment';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import { AddPersonasThreatActorIndividualLines_data$key } from './__generated__/AddPersonasThreatActorIndividualLines_data.graphql';
import { scoRelationshipAdd, scoRelationshipDelete } from './threatActorIndividualMutations';

export const addPersonasThreatActorIndividualLinesQuery = graphql`
  query AddPersonasThreatActorIndividualLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddPersonasThreatActorIndividualLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddPersonasThreatActorIndividualLinesFragment = graphql`
  fragment AddPersonasThreatActorIndividualLines_data on Query
  @refetchable(queryName: "AddPersonasThreatActorIndividualLinesRefetchQuery")
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 },
    cursor: { type: "ID" }
  ) {
    stixCyberObservables(
      search: $search,
      first: $count,
      after: $cursor,
      types: ["Persona"],
    ) @connection(key: "Pagination_stixCyberObservables") {
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

interface AddPersonasThreatActorIndividualLineProps {
  id: string,
  name: string,
  currentTargets: string[],
  handleClick: () => void,
}

const AddPersonasThreatActorIndividualLine: FunctionComponent<
AddPersonasThreatActorIndividualLineProps
> = ({
  id,
  name,
  currentTargets,
  handleClick,
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

interface AddPersonasThreatActorIndividualLinesProps {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
  fragmentKey: AddPersonasThreatActorIndividualLines_data$key,
}

const AddPersonasThreatActorIndividualLines: FunctionComponent<
AddPersonasThreatActorIndividualLinesProps
> = ({
  threatActorIndividual,
  fragmentKey,
}) => {
  const [data, refetch] = useRefetchableFragment(
    AddPersonasThreatActorIndividualLinesFragment,
    fragmentKey,
  );

  useEffect(() => {
    refetch({});
  }, [data]);

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
    const newEdges = edges.filter((n) => n.getLinkedRecord('node')?.getValue('toId') !== deleteId);
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
                name={node.node.persona_name ?? ''}
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
