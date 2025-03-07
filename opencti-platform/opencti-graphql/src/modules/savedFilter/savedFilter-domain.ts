import { type BasicStoreEntitySavedFilter, ENTITY_TYPE_SAVED_FILTER, StoreEntitySavedFilter } from './savedFilter-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import type { QuerySavedFiltersArgs, SavedFilterAddInput } from '../../generated/graphql';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';

export const findAll = (context: AuthContext, user: AuthUser, args: QuerySavedFiltersArgs) => {
  return listEntitiesPaginated<BasicStoreEntitySavedFilter>(context, user, [ENTITY_TYPE_SAVED_FILTER], args);
};
export const addSavedFilter = (context: AuthContext, user: AuthUser, input: SavedFilterAddInput) => {
  return createInternalObject<StoreEntitySavedFilter>(context, user, input, ENTITY_TYPE_SAVED_FILTER);
};
export const deleteSavedFilter = (context: AuthContext, user: AuthUser, savedFilterId: string) => {
  return deleteInternalObject(context, user, savedFilterId, ENTITY_TYPE_SAVED_FILTER);
};
