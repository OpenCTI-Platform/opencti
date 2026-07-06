import { publishUserAction } from '../../listener/UserActionListener';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { updateAttribute } from '../../database/middleware';
import { type BasicStoreEntitySavedFilter, ENTITY_TYPE_SAVED_FILTER, type StoreEntitySavedFilter } from './savedFilter-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { InputMaybe, MemberAccessInput, MutationSavedFilterFieldPatchArgs, QuerySavedFiltersArgs, SavedFilterAddInput } from '../../generated/graphql';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { getUserAccessRight, isUserHasCapability, KNOWLEDGE_KNSHAREFILTERS, MEMBER_ACCESS_CREATOR, MEMBER_ACCESS_RIGHT_ADMIN } from '../../utils/access';
import { addSharedSavedFiltersPermissionChangesCount } from '../../manager/telemetryManager';
import { editAuthorizedMembers } from '../../utils/authorizedMembers';

// saved filters with other members than the creator in restricted_members are considered shared
export const isSavedFilterShared = (savedFilter: BasicStoreEntitySavedFilter) => {
  const creatorId = Array.isArray(savedFilter.creator_id) ? savedFilter.creator_id[0] : savedFilter.creator_id;
  return (savedFilter.restricted_members ?? [])
    .some((m) => m.id && m.id !== creatorId && m.id !== MEMBER_ACCESS_CREATOR);
};

const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntitySavedFilter>(context, user, id, ENTITY_TYPE_SAVED_FILTER);
};

export const findSaveFilterPaginated = (context: AuthContext, user: AuthUser, args: QuerySavedFiltersArgs) => {
  return pageEntitiesConnection<BasicStoreEntitySavedFilter>(context, user, [ENTITY_TYPE_SAVED_FILTER], args);
};

const initializeAuthorizedMembers = (
  authorizedMembers: InputMaybe<MemberAccessInput[]> | undefined,
  user: AuthUser,
) => {
  const initializedAuthorizedMembers = authorizedMembers ?? [];
  if (!authorizedMembers?.some((e) => e.id === user.id)) {
    // add creator to authorized_members on creation
    initializedAuthorizedMembers.push({
      id: user.id,
      access_right: MEMBER_ACCESS_RIGHT_ADMIN,
    });
  }
  return initializedAuthorizedMembers;
};

export const addSavedFilter = (context: AuthContext, user: AuthUser, input: SavedFilterAddInput) => {
  // Force context out of draft to force creation in live index
  const contextOutOfDraft = { ...context, draft_context: '' };
  // construct final creation input
  const canShare = isUserHasCapability(user, KNOWLEDGE_KNSHAREFILTERS);
  const savedFiltersToCreate = {
    ...input,
    restricted_members: initializeAuthorizedMembers(canShare ? input.authorized_members : undefined, user),
  };
  return createInternalObject<StoreEntitySavedFilter>(contextOutOfDraft, user, savedFiltersToCreate, ENTITY_TYPE_SAVED_FILTER);
};

export const deleteSavedFilter = async (context: AuthContext, user: AuthUser, savedFilterId: string) => {
  // Only the creator can delete a saved filter unless the user has the KNOWLEDGE_KNSHAREFILTERS capability
  if (!isUserHasCapability(user, KNOWLEDGE_KNSHAREFILTERS)) {
    const savedFilter = await findById(context, user, savedFilterId);
    if (!savedFilter || savedFilter.creator_id?.[0] !== user.id) {
      throw ForbiddenAccess('You do not have the permission to delete this saved filter');
    }
  }
  // Force context out of draft to force creation in live index
  const contextOutOfDraft = { ...context, draft_context: '' };
  return deleteInternalObject(contextOutOfDraft, user, savedFilterId, ENTITY_TYPE_SAVED_FILTER);
};

export const fieldPatchSavedFilter = async (context: AuthContext, user: AuthUser, args: MutationSavedFilterFieldPatchArgs) => {
  const { id, input } = args;
  const savedFilter = await findById(context, user, id);
  if (!savedFilter) throw FunctionalError('Saved filter cannot be found', { id });
  if (!input) throw FunctionalError('No input given for field patch', { input });

  // Only the creator can update a saved filter unless the user has the KNOWLEDGE_KNSHAREFILTERS capability
  if (!isUserHasCapability(user, KNOWLEDGE_KNSHAREFILTERS)) {
    if (savedFilter.creator_id?.[0] !== user.id) {
      throw ForbiddenAccess('You do not have the permission to update this saved filter');
    }
  }

  const { element } = await updateAttribute<StoreEntitySavedFilter>(context, user, id, ENTITY_TYPE_SAVED_FILTER, input);

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for saved filters \`${element.name}\``,
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
  const args = {
    entityId: savedFilterId,
    input,
    requiredCapabilities: [KNOWLEDGE_KNSHAREFILTERS],
    entityType: ENTITY_TYPE_SAVED_FILTER,
  };
  const before = await findById(context, user, savedFilterId);
  const result = await editAuthorizedMembers(context, user, args);
  if ((before && isSavedFilterShared(before)) || isSavedFilterShared(result)) addSharedSavedFiltersPermissionChangesCount();
  return result;
};

export const getCurrentUserAccessRight = (
  user: AuthUser,
  savedFilter: BasicStoreEntitySavedFilter,
) => {
  return getUserAccessRight(user, savedFilter);
};
