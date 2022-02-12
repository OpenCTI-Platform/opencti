import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Tooltip from '@mui/material/Tooltip';
import Avatar from '@mui/material/Avatar';
import { compose, filter, find, insert, pipe, propEq } from 'ramda';
import inject18n from './i18n';
import { stringToColour } from '../utils/Colors';
import { UserContext } from '../utils/Security';

const SubscriptionAvatarsStyles = () => ({
  avatars: {
    float: 'right',
    display: 'flex',
  },
  avatarsGraph: {
    float: 'right',
    display: 'flex',
    marginTop: -40,
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

const contextUsers = (me, context) => {
  const missingMe = find(propEq('name', me.user_email))(context) === undefined;
  return missingMe ? insert(0, { name: me.user_email }, context) : context;
};

const SubscriptionAvatarsComponent = ({ classes, context, variant }) => {
  const { me } = useContext(UserContext);
  const users = contextUsers(me, context);
  return (
    <div
      className={variant === 'inGraph' ? classes.avatarsGraph : classes.avatars}
    >
      {users.map((user, i) => (
        <Tooltip title={user.name} key={i}>
          <Avatar
            classes={{ root: classes.avatar }}
            style={{ backgroundColor: stringToColour(user.name) }}
          >
            {user.name.charAt(0)}
          </Avatar>
        </Tooltip>
      ))}
    </div>
  );
};

SubscriptionAvatarsComponent.propTypes = {
  classes: PropTypes.object.isRequired,
  context: PropTypes.array.isRequired,
  variant: PropTypes.string,
};

export const SubscriptionAvatars = withStyles(SubscriptionAvatarsStyles)(
  SubscriptionAvatarsComponent,
);

const SubscriptionFocusComponent = ({ t, fieldName, context }) => {
  const { me } = useContext(UserContext);
  const users = contextUsers(me, context);
  const focusedUsers = pipe(
    filter((n) => n.name !== me.user_email),
    filter((n) => n.focusOn === fieldName),
  )(users);
  if (focusedUsers.length === 0) return <span />;
  return (
    <span>
      {focusedUsers.map((user, i) => (
        <span key={i}>
          <span style={{ color: stringToColour(user.name) }}>{user.name}</span>
          <span>{i + 1 < focusedUsers.length ? ', ' : ' '}</span>
        </span>
      ))}
      {focusedUsers.length > 1 ? t('are updating...') : t('is updating...')}
    </span>
  );
};

SubscriptionFocusComponent.propTypes = {
  classes: PropTypes.object.isRequired,
  context: PropTypes.array,
  fieldName: PropTypes.string,
  t: PropTypes.func,
};

export const SubscriptionFocus = compose(
  inject18n,
  withStyles(SubscriptionAvatarsFocusStyles),
)(SubscriptionFocusComponent);
