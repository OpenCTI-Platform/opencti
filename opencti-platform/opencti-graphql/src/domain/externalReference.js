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
import { ENTITY_TYPE_EXT_REF } from '../utils/idGenerator';

export const findById = (externalReferenceId) => {
  return loadEntityById(externalReferenceId, ENTITY_TYPE_EXT_REF);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_EXT_REF], ['source_name', 'description'], args);
};

export const addExternalReference = async (user, externalReference) => {
  const created = await createEntity(user, externalReference, ENTITY_TYPE_EXT_REF, {
    noLog: true,
  });
  return notify(BUS_TOPICS.ExternalReference.ADDED_TOPIC, created, user);
};

export const externalReferenceDelete = async (user, externalReferenceId) => {
  return deleteEntityById(user, externalReferenceId, ENTITY_TYPE_EXT_REF, { noLog: true });
};
export const externalReferenceAddRelation = (user, externalReferenceId, input) => {
  const finalInput = pipe(
    assoc('fromId', externalReferenceId),
    assoc('through', 'external_references'),
    assoc('toType', ENTITY_TYPE_EXT_REF)
  )(input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const externalReferenceDeleteRelation = async (user, externalReferenceId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  const data = await loadEntityById(externalReferenceId, ENTITY_TYPE_EXT_REF);
  return notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, data, user);
};
export const externalReferenceEditField = (user, externalReferenceId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, externalReferenceId, ENTITY_TYPE_EXT_REF, input, wTx, { noLog: true });
  }).then(async () => {
    const externalReference = await loadEntityById(externalReferenceId, ENTITY_TYPE_EXT_REF);
    return notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user);
  });
};

export const externalReferenceCleanContext = (user, externalReferenceId) => {
  delEditContext(user, externalReferenceId);
  return loadEntityById(externalReferenceId, ENTITY_TYPE_EXT_REF).then((externalReference) =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};
export const externalReferenceEditContext = (user, externalReferenceId, input) => {
  setEditContext(user, externalReferenceId, input);
  return loadEntityById(externalReferenceId, ENTITY_TYPE_EXT_REF).then((externalReference) =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};
