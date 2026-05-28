import { publishUserAction } from '../../listener/UserActionListener';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { updateAttribute } from '../../database/middleware';
import { type BasicStoreEntitySavedFilter, ENTITY_TYPE_SAVED_FILTER, type StoreEntitySavedFilter } from './savedFilter-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { MemberAccessInput, MutationSavedFilterFieldPatchArgs, QuerySavedFiltersArgs, SavedFilterAddInput } from '../../generated/graphql';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { getUserAccessRight, KNOWLEDGE_KNSHAREFILTERS, MEMBER_ACCESS_RIGHT_ADMIN } from '../../utils/access';
import { editAuthorizedMembers } from '../../utils/authorizedMembers';
import { isFeatureEnabled } from '../../config/conf';

// Extended input type until codegen is regenerated with the new restricted_members field
interface SavedFilterAddInputWithMembers extends SavedFilterAddInput {
  restricted_members?: MemberAccessInput[] | null;
}

const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntitySavedFilter>(context, user, id, ENTITY_TYPE_SAVED_FILTER);
};

export const findSaveFilterPaginated = (context: AuthContext, user: AuthUser, args: QuerySavedFiltersArgs) => {
  return pageEntitiesConnection<BasicStoreEntitySavedFilter>(context, user, [ENTITY_TYPE_SAVED_FILTER], args);
};
export const addSavedFilter = (context: AuthContext, user: AuthUser, input: SavedFilterAddInputWithMembers) => {
  // Force context out of draft to force creation in live index
  const contextOutOfDraft = { ...context, draft_context: '' };
  const restrictedMembers = input.restricted_members?.length
    ? input.restricted_members
    : [{ id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];
  const savedFiltersToCreate = { ...input, restricted_members: restrictedMembers };
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

export const savedFilterEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  savedFilterId: string,
  input: MemberAccessInput[],
) => {
  if (!isFeatureEnabled('SHARE_FILTERS')) {
    throw ForbiddenAccess('Sharing saved filters is disabled');
  }
  const args = {
    entityId: savedFilterId,
    input,
    requiredCapabilities: [KNOWLEDGE_KNSHAREFILTERS],
    entityType: ENTITY_TYPE_SAVED_FILTER,
  };
  return editAuthorizedMembers(context, user, args);
};

export const getCurrentUserAccessRight = (
  user: AuthUser,
  savedFilter: BasicStoreEntitySavedFilter,
) => {
  return getUserAccessRight(user, savedFilter);
};
