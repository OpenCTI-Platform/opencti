import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { List, ListItemButton, ListItemIcon, ListItemText, useTheme } from '@mui/material';
import ItemIcon from 'src/components/ItemIcon';
import { CheckCircle } from '@mui/icons-material';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { defaultCommitMutation } from 'src/relay/environment';
import { scoRelationshipAdd, scoRelationshipDelete } from '@components/threats/threat_actors_individual/AddIndividualsThreatActorIndividualLines';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import { AddPersonasThreatActorIndividualLines_data$key } from './__generated__/AddPersonasThreatActorIndividualLines_data.graphql';
import { deleteNodeFromEdge } from '../../../../utils/store';

export const addPersonasThreatActorIndividualLinesQuery = graphql`
  query AddPersonasThreatActorIndividualLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $types: [String]
  ) {
    ...AddPersonasThreatActorIndividualLines_data
      @arguments(search: $search, count: $count, cursor: $cursor, types: $types)
  }
`;

const AddPersonasThreatActorIndividualLinesFragment = graphql`
  fragment AddPersonasThreatActorIndividualLines_data on Query
  @refetchable(queryName: "AddPersonasThreatActorIndividualLinesRefetchQuery")
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 },
    cursor: { type: "ID" }
    types: { type: "[String]" }
  ) {
    stixCyberObservables(
      search: $search,
      first: $count,
      after: $cursor,
      types: $types,
    ) @connection(key: "Pagination_tai_stixCyberObservables") {
      edges {
        node {
          id
          observable_value
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
  const data = useFragment(
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

  const handleToggle = (toId: string) => {
    const stixCoreRelationshipId = threatActorIndividual
      .stixCoreRelationships?.edges
      .find(({ node }) => node.to?.id === toId && node.relationship_type === 'known-as')?.node.id;
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

  return (
    <List>
      {data.stixCyberObservables?.edges.map((node, i) => {
        if (node) {
          return (
            <AddPersonasThreatActorIndividualLine
              key={node.node.id}
              id={node.node.id}
              name={node.node.observable_value ?? ''}
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

export default AddPersonasThreatActorIndividualLines;
