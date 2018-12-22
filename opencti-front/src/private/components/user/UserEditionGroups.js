import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, createFragmentContainer, QueryRenderer } from 'react-relay';
import {
  compose, head, map, pathOr, pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemAvatar from '@material-ui/core/ListItemAvatar';
import Checkbox from '@material-ui/core/Checkbox';
import Avatar from '@material-ui/core/Avatar';
import environment from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import { groupsLinesSearchQuery } from '../group/GroupsLines';

const styles = theme => ({
  list: {
    width: '100%',
    maxWidth: 360,
    backgroundColor: theme.palette.background.paper,
  },
});

const userMutationRelationAdd = graphql`
    mutation UserEditionGroupsRelationAddMutation($id: ID!, $input: RelationAddInput!) {
        userEdit(id: $id) {
            relationAdd(input: $input) {
                ...UserEditionGroups_user
            }
        }
    }
`;

class UserEditionGroupsComponent extends Component {
  handleToggle(groupId, event) {
    if (event.target.checked) {
      commitMutation(environment, {
        mutation: userMutationRelationAdd,
        variables: {
          id: this.props.user.id,
          input: {
            fromRole: 'member', toId: groupId, toRole: 'grouping', through: 'membership',
          },
        },
      });
    }
  }

  render() {
    const { classes, user } = this.props;
    console.log(user);
    const userGroups = pipe(
      pathOr([], ['groups', 'edges']),
      map(n => n.node.id),
    )(user);

    return (
      <div>
        <QueryRenderer
          environment={environment}
          query={groupsLinesSearchQuery}
          variables={{ search: 'An' }}
          render={({ error, props }) => {
            if (error) { // Errors
              return <List> &nbsp; </List>;
            }
            if (props) { // Done
              const groups = pipe(
                pathOr([], ['groups', 'edges']),
                map(n => n.node),
              )(props);
              console.log(userGroups);
              return (
                <List dense={true} className={classes.root}>
                  {groups.map(group => (
                    <ListItem key={group.id}>
                      <ListItemAvatar>
                        <Avatar>{group.name.charAt(0)}</Avatar>
                      </ListItemAvatar>
                      <ListItemText primary={group.name}/>
                      <ListItemSecondaryAction>
                        <Checkbox
                          onChange={this.handleToggle.bind(this, group.id)}
                          checked={userGroups.indexOf(group.id) !== -1}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
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
