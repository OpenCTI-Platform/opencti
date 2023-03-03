import * as R from 'ramda';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  paginateAllThings,
  listThings,
  updateAttribute,
} from '../database/middleware';
import { internalLoadById, listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_WORKSPACE } from '../schema/internalObject';
import { FunctionalError } from '../config/errors';
import { ABSTRACT_INTERNAL_RELATIONSHIP, buildRefRelationKey } from '../schema/general';
import { isInternalRelationship, RELATION_HAS_REFERENCE } from '../schema/internalRelationship';
import { generateInternalId } from '../schema/identifier';

export const findById = (context, user, workspaceId) => {
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_WORKSPACE], args);
};

export const objects = async (context, user, workspaceId, args) => {
  const key = buildRefRelationKey(RELATION_HAS_REFERENCE);
  let types = ['Stix-Meta-Object', 'Stix-Core-Object', 'stix-relationship'];
  if (args.types) {
    types = args.types;
  }
  const filters = [{ key, values: [workspaceId] }, ...(args.filters || [])];
  if (args.all) {
    return paginateAllThings(context, user, types, R.assoc('filters', filters, args));
  }
  return listThings(context, user, types, R.assoc('filters', filters, args));
};

export const addWorkspace = async (context, user, workspace) => {
  const workspaceToCreate = R.assoc('internal_id', generateInternalId(), workspace);
  const created = await createEntity(context, user, workspaceToCreate, ENTITY_TYPE_WORKSPACE);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

export const workspaceAddRelation = async (context, user, workspaceId, input) => {
  const data = await internalLoadById(context, user, workspaceId);
  if (data.entity_type !== ENTITY_TYPE_WORKSPACE || !isInternalRelationship(input.relationship_type)) {
    throw FunctionalError('Only stix-internal-relationship can be added through this method.', { workspaceId, input });
  }
  const finalInput = R.assoc('fromId', workspaceId, input);
  return createRelation(context, user, finalInput);
};

export const workspaceAddRelations = async (context, user, workspaceId, input) => {
  const workspace = await storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot add the relation, workspace cannot be found.');
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.map(
    (n) => ({ fromId: workspaceId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(context, user, finalInput);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then((entity) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, entity, user);
  });
};

export const workspaceDeleteRelation = async (context, user, workspaceId, toId, relationshipType) => {
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

export const workspaceDeleteRelations = async (context, user, workspaceId, toIds, relationshipType) => {
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

export const workspaceEditField = async (context, user, workspaceId, input) => {
  const { element } = await updateAttribute(context, user, workspaceId, ENTITY_TYPE_WORKSPACE, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, element, user);
};

export const workspaceDelete = async (context, user, workspaceId) => {
  await deleteElementById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE);
  return workspaceId;
};

// region context
export const workspaceCleanContext = async (context, user, workspaceId) => {
  await delEditContext(user, workspaceId);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE).then((userToReturn) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, userToReturn, user);
  });
};

export const workspaceEditContext = async (context, user, workspaceId, input) => {
  await setEditContext(user, workspaceId, input);
  return storeLoadById(context, user, workspaceId, ENTITY_TYPE_WORKSPACE)
    .then((workspaceToReturn) => notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspaceToReturn, user));
};
// endregion
