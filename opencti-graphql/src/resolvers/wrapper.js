import { contains } from 'ramda';
import { ROLE_ADMIN } from '../config/conf';
import {
  AlreadyAuthError,
  AuthRequiredError,
  ForbiddenError
} from '../config/errors';

const base = wrappedFunction => (_, args, context, info) =>
  wrappedFunction(
    _,
    args,
    context,
    info // isInstance(error) ? error : new UnknownError()
  );

export const anonymous = wrappedFunction => (_, args, context, error) => {
  const baseFunction = base(wrappedFunction)(_, args, context, error);
  if (context.user)
    throw new AlreadyAuthError({ internalData: { user: context.user.email } });
  return baseFunction;
};

export const auth = wrappedFunction => (_, args, context, error) => {
  if (!context.user) throw new AuthRequiredError();
  return base(wrappedFunction)(_, args, context, error);
};

export const admin = wrappedFunction => (_, args, context, error) => {
  const authFunction = auth(wrappedFunction)(_, args, context, error);
  if (!contains(ROLE_ADMIN, context.user.grant))
    throw new ForbiddenError({ internalData: { user: context.user.email } });
  return authFunction;
};
