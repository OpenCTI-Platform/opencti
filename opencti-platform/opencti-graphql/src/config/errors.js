import { createError } from 'apollo-errors';

export const TYPE_AUTH = 'authentication';
const TYPE_TECHNICAL = 'technical';
const TYPE_BUSINESS = 'business';

// TYPE_BUSINESS
export const AuthenticationFailure = createError('AuthenticationFailure', {
  message: 'Wrong name or password',
  data: { type: TYPE_BUSINESS }
});

export const MissingElement = createError('MissingElement', {
  message: 'Please set a functional error message',
  data: { type: TYPE_BUSINESS }
});

export const buildValidationError = field => {
  const ErrorType = createError('Functional', {
    message: `Validation error for ${field}`,
    data: { type: TYPE_BUSINESS }
  });
  return new ErrorType();
};

// TYPE_AUTH
export const AuthRequired = createError('AuthRequired', {
  message: 'You must be logged in to do this.',
  data: { type: TYPE_AUTH }
});

export const ForbiddenAccess = createError('ForbiddenAccess', {
  message: 'You are not allowed to do this.',
  data: { type: TYPE_AUTH }
});

// TYPE_TECHNICAL
export const Unknown = createError('Unknown', {
  message: 'An unknown error has occurred!  Please try again later.',
  data: { type: TYPE_TECHNICAL }
});
