import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import { GroupOutlined, ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { groupsSearchQuery } from '../Groups';
import { isOnlyOrganizationAdmin } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';

const userMutationRelationAdd = graphql`
  mutation UserEditionGroupsRelationAddMutation(
    $id: ID!
    $input: InternalRelationshipAddInput!
  ) {
    userEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...UserEditionGroups_user
        }
      }
    }
  }
`;

const userMutationRelationDelete = graphql`
  mutation UserEditionGroupsRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    userEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...UserEditionGroups_user
      }
    }
  }
`;

const UserEditionGroupsComponent = ({ user }) => {
  const userIsOnlyOrganizationAdmin = isOnlyOrganizationAdmin();
  const { t_i18n } = useFormatter();

  const handleToggle = (groupId, userGroup, event) => {
    if (event.target.checked) {
      commitMutation({
        mutation: userMutationRelationAdd,
        variables: {
          id: user.id,
          input: {
            toId: groupId,
            relationship_type: 'member-of',
          },
        },
      });
    } else if (userGroup !== undefined) {
      commitMutation({
        mutation: userMutationRelationDelete,
        variables: {
          id: user.id,
          toId: userGroup.id,
          relationship_type: 'member-of',
        },
      });
    }
  };

  const userGroups = (user?.groups?.edges ?? []).map((n) => ({
    id: n.node.id,
  }));

  const render = (groups) => {
    return (
      <List>
        {groups.map((group) => {
          const userGroup = userGroups.find((g) => g.id === group.id);
          return (
            <ListItem key={group.id} divider={true}>
              <ListItemIcon color="primary">
                <GroupOutlined />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    {group.name}
                    {group.group_confidence_level === null ? (
                      <Tooltip
                        title={t_i18n('This group has no Max Confidence Level defined.')}
                      >
                        <ReportGmailerrorred fontSize={'small'} color={'error'} style={{ marginLeft: 5 }}/>
                      </Tooltip>
                    ) : (
                      ` (${t_i18n('Max Confidence Level:')} ${group.group_confidence_level.max_confidence})`
                    )}
                  </div>
                }
                secondary={group.description ?? ''}
              />
              <ListItemSecondaryAction>
                <Checkbox
                  onChange={(event) => handleToggle(
                    group.id,
                    userGroup,
                    event,
                  )}
                  checked={userGroup !== undefined}
                />
              </ListItemSecondaryAction>
            </ListItem>
          );
        })}
      </List>
    );
  };
  if (userIsOnlyOrganizationAdmin) {
    return render(user.objectOrganization.edges.flatMap(({ node }) => node.grantable_groups));
  }
  return (
    <QueryRenderer
      query={groupsSearchQuery}
      variables={{ search: '' }}
      render={({ props }) => {
        if (props) {
          // Done
          const groups = (props.groups?.edges ?? []).map((n) => n.node);
          return render(groups);
        }
        // Loading
        return <List> &nbsp; </List>;
      }}
    />
  );
};

UserEditionGroupsComponent.propTypes = {
  user: PropTypes.object,
};

const UserEditionGroups = createFragmentContainer(UserEditionGroupsComponent, {
  user: graphql`
    fragment UserEditionGroups_user on User
    @argumentDefinitions(
      groupsOrderBy: { type: "GroupsOrdering", defaultValue: name }
      groupsOrderMode: { type: "OrderingMode", defaultValue: asc }
      organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
      organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
    ) {
      id
      objectOrganization(orderBy: $organizationsOrderBy, orderMode: $organizationsOrderMode) {
        edges {
          node {
            id
            name
            grantable_groups {
              id
              name
              group_confidence_level{
                max_confidence
              }
            }
          }
        }
      }
      groups(orderBy: $groupsOrderBy, orderMode: $groupsOrderMode) {
        edges {
          node {
            id
            name
          }
        }
      }
      # changes to groups can lead to effective level change
      effective_confidence_level {
        max_confidence
        source {
          ... on User { entity_type id name }
          ... on Group { entity_type id name }
        }
      }
    }
  `,
});

export default UserEditionGroups;
