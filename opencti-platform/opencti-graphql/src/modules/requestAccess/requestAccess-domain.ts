import type { AuthContext, AuthUser } from '../../types/user';
import type { RequestAccessAddInput } from '../../generated/graphql';

export const addRequestAccess = (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  // TODO: create an RFI with the request access
  return input.name;
};

export const validateRequestAccess = (context: AuthContext, user: AuthUser, id: string) => {
  // TODO: return the validation of request
  return id;
};
