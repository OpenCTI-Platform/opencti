import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import Tooltip from '@mui/material/Tooltip';
import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import { filter, insert, pipe } from 'ramda';
import inject18n from './i18n';
import { stringToColour } from '../utils/Colors';
import { UserContext } from '../utils/hooks/useAuth';

const contextUsers = (me, context) => {
  const missingMe = context.find(({ name }) => name === me.user_email) === undefined;
  return missingMe ? insert(0, { name: me.user_email }, context) : context;
};

export const SubscriptionAvatars = ({ context, variant = undefined }) => {
  const { me } = useContext(UserContext);
  const users = contextUsers(me, context);
  return (
    <Box
      sx={variant === 'inGraph'
        ? { float: 'right', display: 'flex', marginTop: '-40px' }
        : { display: 'flex' }}
    >
      {users.map((user, i) => (
        <Tooltip title={user.name} key={i}>
          <Avatar
            sx={{
              width: 28,
              height: 28,
              textTransform: 'uppercase',
            }}
            style={{ backgroundColor: stringToColour(user.name) }}
          >
            {user.name.charAt(0)}
          </Avatar>
        </Tooltip>
      ))}
    </Box>
  );
};

SubscriptionAvatars.propTypes = {
  context: PropTypes.array.isRequired,
  variant: PropTypes.string,
};

const focusedUsersOf = (me, context, fieldName) => pipe(
  filter((n) => n.name !== me.user_email),
  filter((n) => n.focusOn === fieldName),
)(contextUsers(me, context ?? []));

const SubscriptionFocusComponent = ({ t, fieldName, context }) => {
  const { me } = useContext(UserContext);
  const focusedUsers = focusedUsersOf(me, context, fieldName);
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
  context: PropTypes.array,
  fieldName: PropTypes.string,
  t: PropTypes.func,
};

export const SubscriptionFocus = inject18n(SubscriptionFocusComponent);

// The design-system Input keeps a row for any helper, even an empty one: this helper is only set while another
// user edits the field, so an idle form keeps the spacing of its other fields.
export const useSubscriptionFocusHelper = (context) => {
  const { me } = useContext(UserContext);
  return function subscriptionFocusHelper(fieldName) {
    return focusedUsersOf(me, context, fieldName).length > 0
      ? <SubscriptionFocus context={context} fieldName={fieldName} />
      : undefined;
  };
};
