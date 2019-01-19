import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { MoreVert, Person } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';
import UserPopover from './UserPopover';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    fontSize: 13,
  },
  goIcon: {
    position: 'absolute',
    right: 10,
    marginRight: 0,
  },
  itemIconDisabled: {
    color: theme.palette.text.disabled,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.text.disabled,
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  email: {
    float: 'left',
    width: '30%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  firstname: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  lastname: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class UserLineComponent extends Component {
  render() {
    const {
      fd, classes, user, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Person/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              {user.name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.email}>
              {user.email}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.firstname}>
              {user.firstname}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.lastname}>
              {user.lastname}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              {fd(user.created_at)}
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <UserPopover userId={user.id} paginationOptions={paginationOptions}/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

UserLineComponent.propTypes = {
  user: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const UserLineFragment = createFragmentContainer(UserLineComponent, {
  user: graphql`
      fragment UserLine_user on User {
          id,
          name,
          email,
          firstname,
          lastname,
          created_at
      }
  `,
});

export const UserLine = compose(
  inject18n,
  withStyles(styles),
)(UserLineFragment);

class UserLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Person/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              <div className={classes.placeholder} style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.email}>
              <div className={classes.placeholder} style={{ width: '70%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.firstname}>
              <div className={classes.placeholder} style={{ width: '60%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.lastname}>
              <div className={classes.placeholder} style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              <div className={classes.placeholder} style={{ width: 140 }}/>
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <MoreVert/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

UserLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const UserLineDummy = compose(
  inject18n,
  withStyles(styles),
)(UserLineDummyComponent);
