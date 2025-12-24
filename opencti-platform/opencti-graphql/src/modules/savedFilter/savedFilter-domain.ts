import { publishUserAction } from '../../listener/UserActionListener';
import { FunctionalError } from '../../config/errors';
import { updateAttribute } from '../../database/middleware';
import { type BasicStoreEntitySavedFilter, ENTITY_TYPE_SAVED_FILTER, type StoreEntitySavedFilter } from './savedFilter-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { MutationSavedFilterFieldPatchArgs, QuerySavedFiltersArgs, SavedFilterAddInput } from '../../generated/graphql';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { MEMBER_ACCESS_RIGHT_ADMIN } from '../../utils/access';

const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntitySavedFilter>(context, user, id, ENTITY_TYPE_SAVED_FILTER);
};

export const findSaveFilterPaginated = (context: AuthContext, user: AuthUser, args: QuerySavedFiltersArgs) => {
  return pageEntitiesConnection<BasicStoreEntitySavedFilter>(context, user, [ENTITY_TYPE_SAVED_FILTER], args);
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

export const fieldPatchSavedFilter = async (context: AuthContext, user: AuthUser, args: MutationSavedFilterFieldPatchArgs) => {
  const { id, input } = args;
  const savedFilter = await findById(context, user, id);
  if (!savedFilter) throw FunctionalError('Saved filter cannot be found', { id });
  if (!input) throw FunctionalError('No input given for field patch', { input });

  const { element } = await updateAttribute<StoreEntitySavedFilter>(context, user, id, ENTITY_TYPE_SAVED_FILTER, input);

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`filters\` for saved filters \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SAVED_FILTER, input },
  });

  return element;
};
