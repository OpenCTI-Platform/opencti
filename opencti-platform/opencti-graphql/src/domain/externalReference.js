import { assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  internalLoadById,
  listEntities,
  loadById,
  updateAttribute,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';

export const findById = (externalReferenceId) => {
  return loadById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_EXTERNAL_REFERENCE], args);
};

export const addExternalReference = async (user, externalReference) => {
  const created = await createEntity(user, externalReference, ENTITY_TYPE_EXTERNAL_REFERENCE);
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].ADDED_TOPIC, created, user);
};

export const externalReferenceDelete = async (user, externalReferenceId) => {
  return deleteElementById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const externalReferenceAddRelation = async (user, externalReferenceId, input) => {
  const data = await internalLoadById(externalReferenceId);
  if (!data) {
    throw FunctionalError('Cannot add the relation, External Reference cannot be found.');
  }
  if (data.entity_type !== ENTITY_TYPE_EXTERNAL_REFERENCE) {
    throw ForbiddenAccess();
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = assoc('toId', externalReferenceId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const externalReferenceDeleteRelation = async (user, externalReferenceId, fromId, relationshipType) => {
  const externalReference = await loadById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
  if (!externalReference) {
    throw FunctionalError('Cannot delete the relation, External-Reference cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(
    user,
    fromId,
    externalReferenceId,
    relationshipType,
    ABSTRACT_STIX_META_RELATIONSHIP
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
};

export const externalReferenceEditField = async (user, externalReferenceId, input) => {
  const externalReference = await updateAttribute(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
};

export const externalReferenceCleanContext = async (user, externalReferenceId) => {
  await delEditContext(user, externalReferenceId);
  return loadById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) =>
    notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditContext = async (user, externalReferenceId, input) => {
  await setEditContext(user, externalReferenceId, input);
  return loadById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) =>
    notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user)
  );
};
