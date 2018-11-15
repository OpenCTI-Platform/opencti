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

export const anonymous = wrappedFunction => (_, args, { user }, error) => {
  const baseFunction = base(wrappedFunction)(_, args, { user }, error);
  if (user) throw new AlreadyAuthError({ internalData: { user: user.email } });
  return baseFunction;
};

export const auth = wrappedFunction => (_, args, { user }, error) => {
  if (!user) throw new AuthRequiredError();
  return base(wrappedFunction)(_, args, { user }, error);
};

export const admin = wrappedFunction => (_, args, { user }, error) => {
  const authFunction = auth(wrappedFunction)(_, args, { user }, error);
  if (!contains(ROLE_ADMIN, user.roles))
    throw new ForbiddenError({ internalData: { user: user.email } });
  return authFunction;
};
