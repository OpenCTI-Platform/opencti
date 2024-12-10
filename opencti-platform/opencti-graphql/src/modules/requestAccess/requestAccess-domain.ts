import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityRequestAccess, ENTITY_TYPE_REQUEST_ACCESS } from './requestAccess-types';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type {QueryRequestAccessArgs, RequestAccessAddInput} from "../../generated/graphql";

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityRequestAccess>(context, user, id, ENTITY_TYPE_REQUEST_ACCESS);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryRequestAccessArgs) => {
  return listEntitiesPaginated<BasicStoreEntityRequestAccess>(context, user, [ENTITY_TYPE_REQUEST_ACCESS], args);
};

export const addRequestAccess = (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  // TODO: create an RFI with the request access
  return input.name;
};

export const validateRequestAccess = (context: AuthContext, user: AuthUser, id: string) => {
  // TODO: return the validation of request
  return id;
};
