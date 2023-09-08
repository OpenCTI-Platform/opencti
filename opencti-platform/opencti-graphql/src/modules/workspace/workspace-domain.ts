import * as R from 'ramda';
import {
  createEntity,
  deleteElementById,
  listThings,
  paginateAllThings,
  patchAttribute,
  updateAttribute,
} from '../../database/middleware';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { delEditContext, notify, setEditContext } from '../../database/redis';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE } from './workspace-types';
import { FunctionalError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import type {
  EditContext,
  EditInput,
  MemberAccessInput,
  QueryWorkspacesArgs,
  WorkspaceAddInput,
  WorkspaceObjectsArgs
} from '../../generated/graphql';
import { getUserAccessRight, isValidMemberAccessRight, MEMBER_ACCESS_RIGHT_ADMIN } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { containsValidAdmin } from '../../utils/authorizedMembers';
import { elFindByIds } from '../../database/engine';
import type { BasicStoreEntity } from '../../types/store';
import { buildPagination, isEmptyField, READ_DATA_INDICES_WITHOUT_INTERNAL } from '../../database/utils';

export const findById = (context: AuthContext, user: AuthUser, workspaceId: string) => {
  return storeLoadById<BasicStoreEntityWorkspace>(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryWorkspacesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityWorkspace>(context, user, [ENTITY_TYPE_WORKSPACE], args);
};

export const editAuthorizedMembers = async (context: AuthContext, user: AuthUser, workspaceId: string, input: MemberAccessInput[]) => {
  // validate input (validate access right) and remove duplicates
  const filteredInput = input.filter((value, index, array) => {
    return isValidMemberAccessRight(value.access_right) && array.findIndex((e) => e.id === value.id) === index;
  });
  const hasValidAdmin = await containsValidAdmin(context, filteredInput);
  if (!hasValidAdmin) {
    throw FunctionalError('Workspace should have at least one admin');
  }
  const authorizedMembersInput = filteredInput.map((e) => {
    return { id: e.id, access_right: e.access_right };
  });
  const patch = { authorized_members: authorizedMembersInput };
  const { element } = await patchAttribute(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, patch);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};

export const getCurrentUserAccessRight = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace) => {
  return getUserAccessRight(user, workspace);
};

export const getOwnerId = (workspace: BasicStoreEntityWorkspace) => {
  return (Array.isArray(workspace.creator_id) && workspace.creator_id.length > 0) ? workspace.creator_id.at(0) : workspace.creator_id;
};

export const objects = async (context: AuthContext, user: AuthUser, { investigated_entities_ids }: BasicStoreEntityWorkspace, args: WorkspaceObjectsArgs) => {
  if (isEmptyField(investigated_entities_ids)) {
    return buildPagination(0, null, [], 0);
  }
  const filters = [{ key: 'internal_id', values: investigated_entities_ids }, ...(args.filters ?? [])];
  const finalArgs = { ...args, filters };
  if (args.all) {
    return paginateAllThings(context, user, args.types, finalArgs);
  }
  return listThings(context, user, args.types, finalArgs);
};

const checkInvestigatedEntitiesInputs = async (context: AuthContext, user: AuthUser, inputs: EditInput[]): Promise<void> => {
  const addedOrReplacedInvestigatedEntitiesIds = inputs
    .filter(({ key, operation }) => key === 'investigated_entities_ids' && (operation === 'add' || operation === 'replace'))
    .flatMap(({ value }) => value) as string[];
  const opts = { indices: READ_DATA_INDICES_WITHOUT_INTERNAL };
  const entities = await elFindByIds(context, user, addedOrReplacedInvestigatedEntitiesIds, opts) as Array<BasicStoreEntity>;
  const missingEntitiesIds = R.difference(addedOrReplacedInvestigatedEntitiesIds, entities.map((entity) => entity.id));
  if (missingEntitiesIds.length > 0) {
    throw FunctionalError('Invalid ids specified', { ids: missingEntitiesIds });
  }
};

export const addWorkspace = async (context: AuthContext, user: AuthUser, input: WorkspaceAddInput) => {
  const authorizedMembers = input.authorized_members ?? [];
  if (!authorizedMembers.some((e) => e.id === user.id)) {
    // add creator to authorized_members on creation
    authorizedMembers.push({ id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN });
  }
  const workspaceToCreate = { ...input, authorized_members: authorizedMembers };
  const created = await createEntity(context, user, workspaceToCreate, ENTITY_TYPE_WORKSPACE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates ${created.type} workspace \`${created.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

export const workspaceDelete = async (context: AuthContext, user: AuthUser, workspaceId: string) => {
  const deleted = await deleteElementById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes ${deleted.type} workspace \`${deleted.name}\``,
    context_data: { id: workspaceId, entity_type: ENTITY_TYPE_WORKSPACE, input: deleted }
  });
  return workspaceId;
};

export const workspaceEditField = async (context: AuthContext, user: AuthUser, workspaceId: string, inputs: EditInput[]) => {
  await checkInvestigatedEntitiesInputs(context, user, inputs);
  const { element } = await updateAttribute(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, inputs);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};

export const workspaceCleanContext = async (context: AuthContext, user: AuthUser, workspaceId: string) => {
  await delEditContext(user, workspaceId);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then((userToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, userToReturn, user);
  });
};

export const workspaceEditContext = async (context: AuthContext, user: AuthUser, workspaceId: string, input: EditContext) => {
  await setEditContext(user, workspaceId, input);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE)
    .then((workspaceToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspaceToReturn, user));
};
