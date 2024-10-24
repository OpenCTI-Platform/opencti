import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type DraftWorkspaceAddInput, FilterMode, type QueryDraftWorkspaceEntitiesArgs, type QueryDraftWorkspacesArgs } from '../../generated/graphql';
import { createInternalObject } from '../../domain/internalObject';
import { now } from '../../utils/format';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE, type StoreEntityDraftWorkspace } from './draftWorkspace-types';
import { elDeleteDraftContextFromUsers, elDeleteDraftElements } from '../../database/draft-engine';
import { isDraftIndex, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { deleteElementById } from '../../database/middleware';
import type { BasicStoreCommon, BasicStoreEntity } from '../../types/store';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isFeatureEnabled } from '../../config/conf';
import { getDraftContext } from '../../utils/draftContext';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { usersSessionRefresh } from '../../domain/user';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDraftWorkspace>(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspacesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDraftWorkspace>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE], args);
};

export const listDraftObjects = (context: AuthContext, user: AuthUser, args: QueryDraftWorkspaceEntitiesArgs) => {
  let types: string[] = [];
  const { draftId, ...listArgs } = args;
  if (args.types) {
    types = args.types.filter((t) => t && isStixCoreObject(t)) as string[];
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  const newArgs: EntityOptions<BasicStoreEntity> = { ...listArgs, types, indices: [READ_INDEX_DRAFT_OBJECTS] };
  const draftContext = { ...context, draft_context: draftId };
  return listEntitiesPaginated<BasicStoreEntity>(draftContext, user, types, newArgs);
};

export const addDraftWorkspace = async (context: AuthContext, user: AuthUser, input: DraftWorkspaceAddInput) => {
  if (!isFeatureEnabled('DRAFT_WORKSPACE')) throw new Error('Feature not yet available');
  const defaultOps = {
    created_at: now(),
  };
  const draftWorkspaceInput = { ...input, ...defaultOps };
  return createInternalObject<StoreEntityDraftWorkspace>(context, user, draftWorkspaceInput, ENTITY_TYPE_DRAFT_WORKSPACE);
};

const findAllUsersWithDraftContext = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const listArgs = {
    connectionFormat: false,
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['draft_context'], values: [draftId] }], filterGroups: [] }
  };
  return listAllEntities(context, user, [ENTITY_TYPE_USER], listArgs);
};

const deleteDraftContextFromUsers = async (context: AuthContext, user: AuthUser, draftId: string) => {
  const usersWithDraftContext = await findAllUsersWithDraftContext(context, user, draftId);
  if (usersWithDraftContext.length > 0) {
    await elDeleteDraftContextFromUsers(context, user, draftId);
    const usersIds = usersWithDraftContext.map((u) => u.id);
    await usersSessionRefresh(usersIds);
  }
};

export const deleteDraftWorkspace = async (context: AuthContext, user: AuthUser, id: string) => {
  if (getDraftContext(context, user)) throw UnsupportedError('Cannot delete draft while in draft context');
  const draftWorkspace = await findById(context, user, id);
  if (!draftWorkspace) {
    throw FunctionalError(`Draft workspace ${id} cannot be found`, id);
  }

  await elDeleteDraftElements(context, user, id);
  await deleteDraftContextFromUsers(context, user, id);
  await deleteElementById(context, user, id, ENTITY_TYPE_DRAFT_WORKSPACE);

  return id;
};

export const buildDraftVersion = (object: BasicStoreCommon) => {
  if (!isDraftIndex(object._index)) {
    return null;
  }

  if (!object.draft_ids || object.draft_ids.length === 0) {
    throw FunctionalError('Cannot find draft ids on draft entity', { id: object.id });
  }

  return { draft_id: object.draft_ids[0], draft_operation: 'create' };
};
