import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import Avatar from '@material-ui/core/Avatar';
import { compose, filter, pipe } from 'ramda';
import inject18n from './i18n';
import { stringToColour } from '../utils/Colors';

const SubscriptionAvatarsStyles = () => ({
  avatars: {
    float: 'right',
    display: 'flex',
  },
  avatar: {
    width: 28,
    height: 28,
    marginLeft: 10,
    textTransform: 'uppercase',
  },
});

const SubscriptionAvatarsFocusStyles = () => ({
  container: {
    color: '#4CAF50',
  },
});

class SubscriptionAvatarsComponent extends Component {
  render() {
    const { classes, users } = this.props;
    return (
      <div className={classes.avatars}>
        {users.map((user, i) => <Tooltip title={user.username} key={i}>
          <Avatar classes={{ root: classes.avatar }} style={{ backgroundColor: stringToColour(user.username) }}>
            {user.username.charAt(0)}
          </Avatar>
        </Tooltip>)}
      </div>
    );
  }
}

SubscriptionAvatarsComponent.propTypes = {
  classes: PropTypes.object.isRequired,
  users: PropTypes.array,
};

export const SubscriptionAvatars = withStyles(SubscriptionAvatarsStyles)(SubscriptionAvatarsComponent);

class SubscriptionFocusComponent extends Component {
  render() {
    const {t, users, fieldName} = this.props;
    const focusedUsers = filter(n => n.focusOn === fieldName, users);
    if (focusedUsers.length === 0) {
      return <span />;
    }

    return (
      <span>
        {focusedUsers.map((user, i) => (
              <span key={i}><span style={{ color: stringToColour(user.username) }}>{user.username}</span><span>{i + 1 < focusedUsers.length ? ', ' : ' '}</span></span>
        ))}
        {focusedUsers.length > 1 ? t('are updating...') : t('is updating...')}
      </span>
    );
  }
}

SubscriptionFocusComponent.propTypes = {
  classes: PropTypes.object.isRequired,
  me: PropTypes.object,
  users: PropTypes.array,
  fieldName: PropTypes.string,
  t: PropTypes.func,
};

export const SubscriptionFocus = compose(
  inject18n,
  withStyles(SubscriptionAvatarsFocusStyles),
)(SubscriptionFocusComponent);
