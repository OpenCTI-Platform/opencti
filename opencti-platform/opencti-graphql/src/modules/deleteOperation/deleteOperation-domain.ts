import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { QueryDeleteOperationsArgs } from '../../generated/graphql';
import { type BasicStoreEntityDeleteOperation, ENTITY_TYPE_DELETE_OPERATION } from './deleteOperation-types';

export interface DeletedElement {
  id: string
  source_index: string
}

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDeleteOperation>(context, user, id, ENTITY_TYPE_DELETE_OPERATION);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDeleteOperationsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDeleteOperation>(context, user, [ENTITY_TYPE_DELETE_OPERATION], args);
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const restoreDelete = (context: AuthContext, user: AuthUser, id: string) => {
  throw new Error('Restore delete not implemented');
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const completeDelete = (context: AuthContext, user: AuthUser, id: string) => {
  throw new Error('Complete delete not implemented');
};
