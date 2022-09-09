import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose, find, map, pathOr, pipe, propEq } from 'ramda';
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
    $input: InternalRelationshipAddInput
  ) {
    groupEdit(id: $id) {
      relationAdd(input: $input) {
        to {
          ...GroupEditionUsers_group
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
        ...GroupEditionUsers_group
      }
    }
  }
`;

class GroupEditionUsersComponent extends Component {
  handleToggle(userId, groupUser, event) {
    if (event.target.checked) {
      commitMutation({
        mutation: userMutationRelationAdd,
        variables: {
          id: this.props.group.id,
          input: {
            fromId: userId,
            relationship_type: 'member-of',
          },
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
                    const groupUser = find(propEq('id', user.id))(groupUsers);
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

GroupEditionUsersComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  user: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const GroupEditionUsers = createFragmentContainer(GroupEditionUsersComponent, {
  group: graphql`
    fragment GroupEditionUsers_group on Group {
      id
      members {
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

export default compose(inject18n, withStyles(styles))(GroupEditionUsers);
