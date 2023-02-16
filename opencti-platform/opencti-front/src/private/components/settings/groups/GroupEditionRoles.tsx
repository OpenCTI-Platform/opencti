import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation, usePreloadedQuery } from 'react-relay';
import { find, propEq } from 'ramda';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import { Security } from '@mui/icons-material';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import makeStyles from '@mui/styles/makeStyles';
import { GroupEditionRoles_group$data } from './__generated__/GroupEditionRoles_group.graphql';
import { GroupEditionRolesLinesSearchQuery } from './__generated__/GroupEditionRolesLinesSearchQuery.graphql';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  list: {
    width: '100%',
    maxWidth: 360,
    backgroundColor: theme.palette.background.paper,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
}));

const groupEditionAddRoles = graphql`
    mutation GroupEditionRolesRelationAddMutation(
        $id: ID!
        $input: InternalRelationshipAddInput
    ) {
        groupEdit(id: $id) {
            relationAdd(input: $input) {
                from {
                    ...GroupEditionRoles_group
                }
            }
        }
    }
`;

const groupEditionRemoveRoles = graphql`
    mutation GroupEditionRolesRelationDeleteMutation(
        $id: ID!
        $toId: StixRef!
        $relationship_type: String!
    ) {
        groupEdit(id: $id) {
            relationDelete(toId: $toId, relationship_type: $relationship_type) {
                ...GroupEditionRoles_group
            }
        }
    }
`;

export const groupEditionRolesLinesSearchQuery = graphql`
    query GroupEditionRolesLinesSearchQuery($search: String) {
        roles(search: $search) {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
`;

interface GroupEditionRolesComponentProps {
  group: GroupEditionRoles_group$data,
  queryRef: PreloadedQuery<GroupEditionRolesLinesSearchQuery>,
}

const GroupEditionRolesComponent: FunctionComponent<GroupEditionRolesComponentProps> = (
  {
    group,
    queryRef,
  },
) => {
  const classes = useStyles();
  const { roles } = usePreloadedQuery<GroupEditionRolesLinesSearchQuery>(
    groupEditionRolesLinesSearchQuery,
    queryRef,
  );
  const rolesData = (roles?.edges ?? []).map((n) => n?.node) as { id: string, name: string }[];
  const groupRoles = (group.roles ?? []).map((n) => ({ id: n?.id }));
  const [commitAddRole] = useMutation(groupEditionAddRoles);
  const [commitRemoveRole] = useMutation(groupEditionRemoveRoles);

  const handleToggle = (roleId?: string, groupRole?: { id: string }, event?: React.ChangeEvent<HTMLInputElement>) => {
    if (event?.target.checked) {
      commitAddRole({
        variables: {
          id: group.id,
          input: {
            toId: roleId,
            relationship_type: 'has-role',
          },
        },
      });
    } else if (groupRole !== undefined) {
      commitRemoveRole({
        variables: {
          id: group.id,
          toId: groupRole.id,
          relationship_type: 'has-role',
        },
      });
    }
  };

  return (
    <List className={classes.root}>
      {rolesData.sort((roleA, roleB) => roleA.name.localeCompare(roleB.name)).map((role) => {
        const groupRole = find(propEq('id', role.id))(groupRoles);
        return (
          <ListItem key={group.id} divider={true}>
            <ListItemIcon color="primary">
              <Security />
            </ListItemIcon>
            <ListItemText
              primary={role.name}
            />
            <ListItemSecondaryAction>
              <Checkbox
                onChange={(event) => handleToggle(
                  role.id,
                  groupRole,
                  event,
                )}
                checked={groupRole !== undefined}
              />
            </ListItemSecondaryAction>
          </ListItem>
        );
      })}
    </List>
  );
};

const GroupEditionRoles = createFragmentContainer(GroupEditionRolesComponent, {
  group: graphql`
      fragment GroupEditionRoles_group on Group {
          id
          roles {
              ... on Role {
                  id
                  name
              }
          }
      }
  `,
});

export default GroupEditionRoles;
