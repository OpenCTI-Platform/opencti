import { isInstance } from 'apollo-errors';
import { contains } from 'ramda';
import { ROLE_ADMIN } from '../config/conf';
import {
  AlreadyAuthenticatedError,
  AuthenticationRequiredError,
  ForbiddenError,
  UnknownError
} from '../config/errors';

const base = wrappedFunction => (_, args, context, error) =>
  wrappedFunction(
    _,
    args,
    context,
    isInstance(error) ? error : new UnknownError()
  );

export const anonymous = wrappedFunction => (_, args, { user }, error) => {
  const baseFunction = base(wrappedFunction)(_, args, { user }, error);
  if (user) throw new AlreadyAuthenticatedError();
  return baseFunction;
};

export const auth = wrappedFunction => (_, args, { user }, error) => {
  if (!user) throw new AuthenticationRequiredError();
  return base(wrappedFunction)(_, args, { user }, error);
};

export const admin = wrappedFunction => (_, args, { user }, error) => {
  const authFunction = auth(wrappedFunction)(_, args, { user }, error);
  if (!contains(ROLE_ADMIN, user.roles)) throw new ForbiddenError();
  return authFunction;
};
