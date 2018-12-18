import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer, QueryRenderer } from 'react-relay';
import {
  compose, map, pathOr, pipe,
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

class UserEditionGroupsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { checked: [] };
  }

  handleToggle(groupId) {
    console.log(event);
  }

  render() {
    const { classes, t } = this.props;
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
              return (
                <List dense={true} className={classes.root}>
                  {groups.map(group => (
                    <ListItem key={group.id} button={true} onClick={this.handleToggle.bind(this, group.id)}>
                      <ListItemAvatar>
                        <Avatar>{group.name.charAt(0)}</Avatar>
                      </ListItemAvatar>
                      <ListItemText primary={group.name}/>
                      <ListItemSecondaryAction>
                        <Checkbox
                          onChange={this.handleToggle.bind(this, group.id)}
                          checked={this.state.checked.indexOf(group.id) !== -1}
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
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(UserEditionGroups);
