import * as R from 'ramda';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listThings,
  paginateAllThings,
  patchAttribute,
  updateAttribute,
} from '../../database/middleware';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { delEditContext, notify, setEditContext } from '../../database/redis';
import { BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE } from './workspace-types';
import { FunctionalError } from '../../config/errors';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from '../../schema/general';
import { isInternalRelationship } from '../../schema/internalRelationship';
import type { AuthContext, AuthUser } from '../../types/user';
import type {
  EditContext,
  EditInput,
  MemberAccessInput,
  QueryWorkspacesArgs,
  StixRefRelationshipAddInput,
  StixRefRelationshipsAddInput,
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

export const workspaceAddRelation = async (context: AuthContext, user: AuthUser, workspaceId: string, input: StixRefRelationshipAddInput) => {
  const data = await internalLoadById(context, user, workspaceId);
  if (data.entity_type !== ENTITY_TYPE_WORKSPACE || !isInternalRelationship(input.relationship_type)) {
    throw FunctionalError('Only stix-internal-relationship can be added through this method.', { workspaceId, input });
  }
  const finalInput = { ...input, fromId: workspaceId };
  return createRelation(context, user, finalInput);
};

export const workspaceAddRelations = async (context: AuthContext, user: AuthUser, workspaceId: string, input: StixRefRelationshipsAddInput) => {
  const workspace = await storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot add the relation, workspace cannot be found.');
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  if (!input.toIds) {
    throw FunctionalError('Cannot add relations, toIds argument is not defined.');
  }
  const finalInput = input.toIds.map(
    (n) => ({ fromId: workspaceId, toId: n, relationship_type: input.relationship_type })
  );
  await createRelations(context, user, finalInput);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then((entity) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, entity, user);
  });
};

export const workspaceDeleteRelation = async (context: AuthContext, user: AuthUser, workspaceId: string, toId: string, relationshipType: string) => {
  const workspace = await storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot delete the relation, workspace cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(context, user, workspaceId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user);
};

export const workspaceDeleteRelations = async (context: AuthContext, user: AuthUser, workspaceId: string, toIds: string[], relationshipType: string) => {
  const workspace = await storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot delete the relation, workspace cannot be found.');
  }
  if (!isInternalRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  for (let i = 0; i < toIds.length; i += 1) {
    await deleteRelationsByFromAndTo(context, user, workspaceId, toIds[i], relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user);
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

const checkInvestigatedEntitiesInputs = async (AddedOrReplacedInvestigatedEntitiesIds: (string | null)[], context: AuthContext, user: AuthUser): Promise<void> => {
  const entities = await elFindByIds(context, user, AddedOrReplacedInvestigatedEntitiesIds) as Array<BasicStoreEntity>;

  checkMissingEntities(AddedOrReplacedInvestigatedEntitiesIds, entities);
  checkEntitiesAreInvestigable(entities);
};

export const workspaceEditField = async (context: AuthContext, user: AuthUser, workspaceId: string, inputs: EditInput[]) => {
  const addedOrReplacedInvestigatedEntitiesIds = inputs
    .filter(({ key, operation }) => key === 'investigated_entities_ids' && (operation === 'add' || operation === 'replace'))
    .flatMap(({ value }) => value);

  if (addedOrReplacedInvestigatedEntitiesIds.length > 0) {
    await checkInvestigatedEntitiesInputs(addedOrReplacedInvestigatedEntitiesIds, context, user);
  }

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
