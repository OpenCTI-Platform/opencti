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
import { BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE } from './workspace-types';
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

const INVESTIGABLE_TYPES: string[] = ['Stix-Meta-Object', 'Stix-Core-Object', 'stix-relationship'];

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
  const types = args.types ?? INVESTIGABLE_TYPES;

  if (!investigated_entities_ids) {
    return { edges: [] };
  }

  const filters = [
    { key: 'internal_id', values: investigated_entities_ids },
    ...(args.filters ?? [])
  ];
  const finalArgs = { ...args, filters };
  if (args.all) {
    return paginateAllThings(context, user, types, finalArgs);
  }
  return listThings(context, user, types, finalArgs);
};

const isEntityInvestigable = (entity: BasicStoreEntity): boolean => {
  const matching_types = INVESTIGABLE_TYPES
    .filter((investigable_type) => entity.parent_types.includes(investigable_type));

  return matching_types.length !== 0;
};

const checkEntitiesAreInvestigable = (entities: Array<BasicStoreEntity>): void => {
  entities
    .filter((entity) => !isEntityInvestigable(entity))
    .forEach((entity) => { throw FunctionalError(`Entity with id '${entity.id}' of type '${entity.entity_type}' is not investigable.`); });
};

const checkMissingEntities = (AddedOrReplacedinvestigatedEntitiesIds: (string | null)[], entities: Array<BasicStoreEntity>): void => {
  const missingEntitiesIds = R.difference(AddedOrReplacedinvestigatedEntitiesIds, entities.map((entity) => entity.id));

  if (missingEntitiesIds.length > 0) {
    throw FunctionalError(`Entities with ids '${missingEntitiesIds.join(', ')}' were not found. Cannot conduct investigation.`);
  }
};

const checkInvestigatedEntitiesInputs = async (context: AuthContext, user: AuthUser, AddedOrReplacedInvestigatedEntitiesIds: string[]): Promise<void> => {
  const entities = await elFindByIds(context, user, AddedOrReplacedInvestigatedEntitiesIds) as Array<BasicStoreEntity>;

  checkMissingEntities(AddedOrReplacedInvestigatedEntitiesIds, entities);
  checkEntitiesAreInvestigable(entities);
};

export const addWorkspace = async (context: AuthContext, user: AuthUser, input: WorkspaceAddInput) => {
  const authorizedMembers = input.authorized_members ?? [];
  if (!authorizedMembers.some((e) => e.id === user.id)) {
    // add creator to authorized_members on creation
    authorizedMembers.push({ id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN });
  }

  await checkInvestigatedEntitiesInputs(context, user, (input.investigated_entities_ids ?? []) as string[]);

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
  const addedOrReplacedInvestigatedEntitiesIds = inputs
    .filter(({ key, operation }) => key === 'investigated_entities_ids' && (operation === 'add' || operation === 'replace'))
    .flatMap(({ value }) => value) as string[];

  await checkInvestigatedEntitiesInputs(context, user, addedOrReplacedInvestigatedEntitiesIds);

  const { element } = await updateAttribute(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, inputs);

  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};

// region context
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

// endregion
