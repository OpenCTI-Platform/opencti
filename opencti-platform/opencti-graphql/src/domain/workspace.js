import * as R from 'ramda';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteElementById,
  deleteRelationsByFromAndTo,
  internalLoadById,
  listAllThings,
  listEntities,
  listThings,
  loadById,
  updateAttribute,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { ENTITY_TYPE_WORKSPACE } from '../schema/internalObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { FunctionalError } from '../config/errors';
import { ABSTRACT_STIX_META_RELATIONSHIP, REL_INDEX_PREFIX } from '../schema/general';
import { isStixMetaRelationship, RELATION_OBJECT } from '../schema/stixMetaRelationship';

export const findById = (user, workspaceId) => {
  return loadById(user, workspaceId, ENTITY_TYPE_WORKSPACE);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_WORKSPACE], args);
};

export const objects = async (user, workspaceId, args) => {
  const key = `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`;
  let types = ['Stix-Core-Object', 'stix-core-relationship'];
  if (args.types) {
    types = args.types;
  }
  const filters = [{ key, values: [workspaceId] }, ...(args.filters || [])];
  if (args.all) {
    return listAllThings(user, types, R.assoc('filters', filters, args));
  }
  return listThings(user, types, R.assoc('filters', filters, args));
};

export const addWorkspace = async (user, workspace) => {
  const created = await createEntity(user, workspace, ENTITY_TYPE_WORKSPACE);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

export const workspaceAddRelation = async (user, workspaceId, input) => {
  const data = await internalLoadById(user, workspaceId);
  if (data.entity_type !== ENTITY_TYPE_WORKSPACE || !isStixRelationship(input.relationship_type)) {
    throw FunctionalError('Only stix-meta-relationship can be added through this method.', { workspaceId, input });
  }
  const finalInput = R.assoc('fromId', workspaceId, input);
  return createRelation(user, finalInput);
};

export const workspaceAddRelations = async (user, workspaceId, input) => {
  const workspace = await loadById(user, workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot add the relation, workspace cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = R.map(
    (n) => ({ fromId: workspaceId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(user, finalInput);
  return loadById(user, workspaceId, ENTITY_TYPE_WORKSPACE).then((entity) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, entity, user)
  );
};

export const workspaceDeleteRelation = async (user, workspaceId, toId, relationshipType) => {
  const workspace = await loadById(user, workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot delete the relation, workspace cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, workspaceId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user);
};

export const workspaceEditField = async (user, workspaceId, input) => {
  const workspace = await updateAttribute(user, workspaceId, ENTITY_TYPE_WORKSPACE, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user);
};

export const workspaceDelete = async (user, workspaceId) => {
  await deleteElementById(user, workspaceId, ENTITY_TYPE_WORKSPACE);
  return workspaceId;
};

// region context
export const workspaceCleanContext = async (user, workspaceId) => {
  await delEditContext(user, workspaceId);
  return loadById(user, workspaceId, ENTITY_TYPE_WORKSPACE).then((userToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, userToReturn, user)
  );
};

export const workspaceEditContext = async (user, workspaceId, input) => {
  await setEditContext(user, workspaceId, input);
  return loadById(user, workspaceId, ENTITY_TYPE_WORKSPACE).then((workspaceToReturn) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspaceToReturn, user)
  );
};
// endregion
