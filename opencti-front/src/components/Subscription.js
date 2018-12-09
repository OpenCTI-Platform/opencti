import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import Avatar from '@material-ui/core/Avatar';
import { compose } from 'ramda';
import { pickColor } from '../utils/Colors';
import inject18n from './i18n';

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
          <Avatar classes={{ root: classes.avatar }} style={{ backgroundColor: pickColor(i) }}>
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
    const { classes, t, users, fieldName } = this.props;
    let display = false;
    return (
      <span>
        {users.map((user, i) => {
          if (user.focusOn === fieldName) {
            display = true;
            return (
              <span key={i}><span style={{ color: pickColor(i) }}>{user.username}</span><span>{i + 1 < users.length ? ', ' : ' '}</span></span>
            );
          }
          return <span key={i}/>;
        })
        }
        {display ? users.length > 1 ? t('are updating...') : t('is updating...') : ''}
      </span>
    );
  }
}

SubscriptionFocusComponent.propTypes = {
  classes: PropTypes.object.isRequired,
  users: PropTypes.array,
  fieldName: PropTypes.string,
  t: PropTypes.func,
};

export const SubscriptionFocus = compose(
  inject18n,
  withStyles(SubscriptionAvatarsFocusStyles),
)(SubscriptionFocusComponent);
