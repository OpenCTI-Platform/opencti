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
import ListItemAvatar from '@material-ui/core/ListItemAvatar';
import Checkbox from '@material-ui/core/Checkbox';
import Avatar from '@material-ui/core/Avatar';
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
    $input: RelationAddInput!
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
  mutation UserEditionGroupsRelationDeleteMutation($id: ID!, $relationId: ID!) {
    userEdit(id: $id) {
      relationDelete(relationId: $relationId) {
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
            fromRole: 'member',
            toId: groupId,
            toRole: 'grouping',
            through: 'membership',
          },
        },
      });
    } else if (userGroup !== undefined) {
      commitMutation({
        mutation: userMutationRelationDelete,
        variables: {
          id: this.props.user.id,
          relationId: userGroup.relation,
        },
      });
    }
  }

  render() {
    const { classes, user } = this.props;
    const userGroups = pipe(
      pathOr([], ['groups', 'edges']),
      map((n) => ({ id: n.node.id, relation: n.relation.id })),
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
                <List dense={true} className={classes.root}>
                  {groups.map((group) => {
                    const userGroup = find(propEq('id', group.id))(userGroups);
                    return (
                      <ListItem key={group.id} divider={true}>
                        <ListItemAvatar>
                          <Avatar className={classes.avatar}>
                            {group.name.charAt(0)}
                          </Avatar>
                        </ListItemAvatar>
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
          relation {
            id
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
