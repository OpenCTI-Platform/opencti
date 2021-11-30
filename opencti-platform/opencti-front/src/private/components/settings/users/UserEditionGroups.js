/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import {
  compose, map, pathOr, pipe, propOr, propEq, find,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Checkbox from '@material-ui/core/Checkbox';
import { GroupOutlined } from '@material-ui/icons';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { groupsSearchQuery } from '../Groups';

const styles = (theme) => ({
  list: {
    width: '100%',
    maxWidth: 360,
    backgroundColor: theme.palette.background.paper,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
});

const userMutationRelationAdd = graphql`
  mutation UserEditionGroupsRelationAddMutation(
    $id: ID!
    $input: InternalRelationshipAddInput
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
    $toId: String!
    $relationship_type: String!
  ) {
    userEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...UserEditionGroups_user
      }
    }
  }
`;

class UserEditionGroupsComponent extends Component {
  handleToggle(groupId, userGroup, event) {
    if (event.target.checked) {
      commitMutation({
        mutation: userMutationRelationAdd,
        variables: {
          id: this.props.user.id,
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
          id: this.props.user.id,
          toId: userGroup.id,
          relationship_type: 'member-of',
        },
      });
    }
  }

  render() {
    const { classes, user } = this.props;
    const userGroups = pipe(
      pathOr([], ['groups', 'edges']),
      map((n) => ({ id: n.node.id })),
    )(user);
    return (
      <div>
        <QueryRenderer
          query={groupsSearchQuery}
          variables={{ search: '' }}
          render={({ props }) => {
            if (props) {
              // Done
              const groups = pipe(
                pathOr([], ['groups', 'edges']),
                map((n) => n.node),
              )(props);
              return (
                <List >
                  {groups.map((group) => {
                    const userGroup = find(propEq('id', group.id))(userGroups);
                    return (
                      <ListItem key={group.id} divider={true}>
                        <ListItemIcon color="primary">
                          <GroupOutlined />
                        </ListItemIcon>
                        <ListItemText
                          primary={group.name}
                          secondary={propOr('-', 'description', group)}
                        />
                        <ListItemSecondaryAction>
                          <Checkbox
                            onChange={this.handleToggle.bind(
                              this,
                              group.id,
                              userGroup,
                            )}
                            checked={userGroup !== undefined}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    );
                  })}
                </List>
              );
            }
            // Loading
            return <List> &nbsp; </List>;
          }}
        />
      </div>
    );
  }
}

UserEditionGroupsComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  user: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const UserEditionGroups = createFragmentContainer(UserEditionGroupsComponent, {
  user: graphql`
    fragment UserEditionGroups_user on User {
      id
      groups {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(UserEditionGroups);
