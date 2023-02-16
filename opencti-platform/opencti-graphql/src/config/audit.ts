// region global
export const ACCESS_CONTROL = 'ACCESS_CONTROL';
// endregion

// region login
export const IMPERSONATE_ACTION = 'IMPERSONATE';
export const LOGIN_ACTION = 'LOGIN';
export const LOGOUT_ACTION = 'LOGOUT';
// endregion

// region files
export const UPLOAD_ACTION = 'UPLOAD';
// endregion

// region users / roles / groups
export const USER_CREATION = 'USER_CREATION';
export const USER_DELETION = 'USER_DELETION';

export const ROLE_CREATION = 'ROLE_CREATION';
export const ROLE_DELETION = 'ROLE_DELETION';

export const GROUP_CREATION = 'GROUP_CREATION';
// endregion

export const convertRelationToAction = (name: string, isAdd = true): string => {
  let convertName = 'UNDEFINED';
  if (name === 'has-role') {
    convertName = 'ROLE';
  }
  if (name === 'member-of') {
    convertName = 'GROUP';
  }
  if (name === 'participate-to') {
    convertName = 'ORGANIZATION';
  }
  return isAdd ? `${convertName}_ADD` : `${convertName}_REMOVE`;
};
