import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { compose, map, pathOr, pipe } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import { PersonOutlined } from '@mui/icons-material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { usersLinesSearchQuery } from '../users/UsersLines';
import { deleteNodeFromId, insertNode } from '../../../../utils/store';

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
  mutation GroupEditionUsersRelationAddMutation(
    $id: ID!
    $input: InternalRelationshipAddInput!
  ) {
    groupEdit(id: $id) {
      relationAdd(input: $input) {
        to {
          ...GroupEditionContainer_group
        }
        from {
          ...UserLine_node
        }
      }
    }
  }
`;

const userMutationRelationDelete = graphql`
  mutation GroupEditionUsersRelationDeleteMutation(
    $id: ID!
    $fromId: StixRef!
    $relationship_type: String!
  ) {
    groupEdit(id: $id) {
      relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
        id
        ...GroupEditionContainer_group
      }
    }
  }
`;

class GroupEditionUsers extends Component {
  handleToggle(userId, groupUser, event) {
    const options = { ...this.props.paginationOptions };
    Object.keys(options).forEach((key) => options[key] === undefined && delete options[key]);
    if (event.target.checked) {
      const input = {
        fromId: userId,
        relationship_type: 'member-of',
      };
      commitMutation({
        mutation: userMutationRelationAdd,
        variables: {
          id: this.props.group.id,
          input,
        },
        updater: (store) => {
          insertNode(
            store,
            'Pagination_group_members',
            options,
            'groupEdit',
            this.props.group.id,
            'relationAdd',
            input,
            'from',
          );
        },
      });
    } else if (groupUser !== undefined) {
      commitMutation({
        mutation: userMutationRelationDelete,
        variables: {
          id: this.props.group.id,
          fromId: groupUser.id,
          relationship_type: 'member-of',
        },
        updater: (store) => {
          deleteNodeFromId(store, this.props.group.id, 'Pagination_group_members', options, groupUser.id);
        },
      });
    }
  }

  render() {
    const { classes, group } = this.props;
    const groupUsers = pipe(
      pathOr([], ['members', 'edges']),
      map((n) => ({ id: n.node.id })),
    )(group);
    return (
      <div>
        <QueryRenderer
          query={usersLinesSearchQuery}
          variables={{ search: '' }}
          render={({ props }) => {
            if (props) {
              const users = pipe(
                pathOr([], ['users', 'edges']),
                map((n) => n.node),
              )(props);
              return (
                <List dense={true} className={classes.root}>
                  {users.map((user) => {
                    const groupUser = groupUsers.find((g) => g.id === user.id);
                    return (
                      <ListItem key={group.id} divider={true}>
                        <ListItemIcon color="primary">
                          <PersonOutlined />
                        </ListItemIcon>
                        <ListItemText
                          primary={user.name}
                          secondary={user.user_email}
                        />
                        <ListItemSecondaryAction>
                          <Checkbox
                            onChange={this.handleToggle.bind(
                              this,
                              user.id,
                              groupUser,
                            )}
                            checked={groupUser !== undefined}
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

GroupEditionUsers.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  user: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(GroupEditionUsers);
