import { createError } from 'apollo-errors';

export const LEVEL_WARNING = 'warning';
export const LEVEL_ERROR = 'error';
export const TYPE_AUTH = 'authentication';
export const TYPE_TECHNICAL = 'technical';
const TYPE_BUSINESS = 'business';

const error = (type, message, data) => {
  const Exception = createError(type, { data, message });
  return new Exception();
};

export const AuthenticationFailure = (reason, data) =>
  error(TYPE_TECHNICAL, 'Wrong name or password', {
    reason: 'AuthenticationFailure',
    type: TYPE_BUSINESS,
    ...data,
  });

// TYPE_AUTH
export const AuthRequired = (reason, data) =>
  error(TYPE_TECHNICAL, 'You must be logged in to do this.', {
    reason: 'Authenticated user is required',
    type: TYPE_AUTH,
    ...data,
  });

export const ForbiddenAccess = (reason, data) =>
  error(TYPE_TECHNICAL, 'You are not allowed to do this.', {
    reason: 'ForbiddenAccess',
    type: TYPE_AUTH,
    ...data,
  });

// TYPE_TECHNICAL
export const DatabaseError = (reason, data) =>
  error(TYPE_TECHNICAL, 'A database error has occurred', {
    reason: reason || 'No reason specify',
    type: 'DatabaseError',
    ...data,
  });

export const ConfigurationError = (reason, data) =>
  error(TYPE_TECHNICAL, 'A configuration error has occurred', {
    reason: reason || 'No reason specify',
    ...data,
  });

export const UnknownError = (reason, data) =>
  error(TYPE_TECHNICAL, 'An unknown error has occurred', {
    reason: reason || 'No reason specify',
    type: 'UnknownError',
    ...data,
  });

export const FunctionalError = (reason, data) =>
  error(TYPE_BUSINESS, 'Business validation', {
    reason: reason || 'No reason specify',
    ...data,
  });

export const ValidationError = (field, data) =>
  error(TYPE_BUSINESS, 'Validation error', {
    reason: `Invalid field ${field}`,
    ...data,
  });
