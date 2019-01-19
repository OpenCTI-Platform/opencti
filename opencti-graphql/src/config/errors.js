import { createError } from 'apollo-errors';

export const LoginError = createError('LoginError', {
  message: 'Wrong name or password'
});

export const UnknownError = createError('UnknownError', {
  message: 'An unknown error has occurred!  Please try again later'
});

export const AuthRequiredError = createError('AuthRequiredError', {
  message: 'You must be logged in to do this'
});

export const AlreadyAuthError = createError('AlreadyAuthError', {
  message: 'You are already authenticated'
});

export const ForbiddenError = createError('ForbiddenError', {
  message: 'You are not allowed to do this'
});

export const FunctionalError = createError('FunctionalError', {
  message: 'Please set a functional error message'
});
