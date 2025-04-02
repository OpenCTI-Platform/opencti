import { type BasicStoreEntitySavedFilter, ENTITY_TYPE_SAVED_FILTER, type StoreEntitySavedFilter } from './savedFilter-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import type { QuerySavedFiltersArgs, SavedFilterAddInput } from '../../generated/graphql';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { MEMBER_ACCESS_RIGHT_ADMIN } from '../../utils/access';

export const findAll = (context: AuthContext, user: AuthUser, args: QuerySavedFiltersArgs) => {
  return listEntitiesPaginated<BasicStoreEntitySavedFilter>(context, user, [ENTITY_TYPE_SAVED_FILTER], args);
};
export const addSavedFilter = (context: AuthContext, user: AuthUser, input: SavedFilterAddInput) => {
  // Force context out of draft to force creation in live index
  const contextOutOfDraft = { ...context, draft_context: '' };
  const savedFiltersToCreate = { ...input, restricted_members: [{ id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }] };
  return createInternalObject<StoreEntitySavedFilter>(contextOutOfDraft, user, savedFiltersToCreate, ENTITY_TYPE_SAVED_FILTER);
};
export const deleteSavedFilter = (context: AuthContext, user: AuthUser, savedFilterId: string) => {
  // Force context out of draft to force creation in live index
  const contextOutOfDraft = { ...context, draft_context: '' };
  return deleteInternalObject(contextOutOfDraft, user, savedFilterId, ENTITY_TYPE_SAVED_FILTER);
};
