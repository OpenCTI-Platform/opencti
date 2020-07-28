import { pipe, assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  executeWrite,
  listEntities,
  loadEntityById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, RELATION_EXTERNAL_REFERENCE } from '../utils/idGenerator';

export const findById = (externalReferenceId) => {
  return loadEntityById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_EXTERNAL_REFERENCE], ['source_name', 'description'], args);
};

export const addExternalReference = async (user, externalReference) => {
  const created = await createEntity(user, externalReference, ENTITY_TYPE_EXTERNAL_REFERENCE, {
    noLog: true,
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].ADDED_TOPIC, created, user);
};

export const externalReferenceDelete = async (user, externalReferenceId) => {
  return deleteEntityById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE, { noLog: true });
};

export const externalReferenceAddRelation = (user, externalReferenceId, input) => {
  const finalInput = pipe(
    assoc('toId', externalReferenceId),
    assoc('relationship_type', RELATION_EXTERNAL_REFERENCE)
  )(input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const externalReferenceDeleteRelation = async (user, externalReferenceId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  const data = await loadEntityById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, data, user);
};

export const externalReferenceEditField = (user, externalReferenceId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE, input, wTx, { noLog: true });
  }).then(async () => {
    const externalReference = await loadEntityById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
    return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
  });
};

export const externalReferenceCleanContext = async (user, externalReferenceId) => {
  await delEditContext(user, externalReferenceId);
  return loadEntityById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) =>
    notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditContext = async (user, externalReferenceId, input) => {
  await setEditContext(user, externalReferenceId, input);
  return loadEntityById(externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) =>
    notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user)
  );
};
