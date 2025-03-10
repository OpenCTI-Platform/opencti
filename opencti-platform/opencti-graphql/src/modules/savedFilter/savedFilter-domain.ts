import { addFilter } from '../../utils/filtering/filtering-utils';
import { type BasicStoreEntitySavedFilter, ENTITY_TYPE_SAVED_FILTER, StoreEntitySavedFilter } from './savedFilter-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import type { QuerySavedFiltersArgs, SavedFilterAddInput } from '../../generated/graphql';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';

export const findAll = (context: AuthContext, user: AuthUser, args: QuerySavedFiltersArgs) => {
  const queryFilters = addFilter(args.filters, 'creator_id', user.id);
  const queryArgs = { ...args, filters: queryFilters };
  return listEntitiesPaginated<BasicStoreEntitySavedFilter>(context, user, [ENTITY_TYPE_SAVED_FILTER], queryArgs);
};
export const addSavedFilter = (context: AuthContext, user: AuthUser, input: SavedFilterAddInput) => {
  return createInternalObject<StoreEntitySavedFilter>(context, user, input, ENTITY_TYPE_SAVED_FILTER);
};
export const deleteSavedFilter = (context: AuthContext, user: AuthUser, savedFilterId: string) => {
  // TODO: vérifier que le filtre appartient bien à l'utilisateur
  // TODO: Vérifier la capa ByPass pour éviter de bloquer l'action d'un admin
  // TODO : add tests
  return deleteInternalObject(context, user, savedFilterId, ENTITY_TYPE_SAVED_FILTER);
};
