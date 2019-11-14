import { assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  listEntities,
  loadEntityById,
  paginate,
  TYPE_STIX_DOMAIN,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = externalReferenceId => {
  return loadEntityById(externalReferenceId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['External-Reference'], args);
  return listEntities(['source_name', 'description'], typedArgs);
};

export const findByEntity = async args => {
  const test = await paginate(
    `match $e isa External-Reference; 
    $rel(external_reference:$e, so:$so) isa external_references;
    $so has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
  return test;
};

export const addExternalReference = async (user, externalReference) => {
  const created = await createEntity(externalReference, 'External-Reference', TYPE_STIX_DOMAIN);
  return notify(BUS_TOPICS.ExternalReference.ADDED_TOPIC, created, user);
};

export const externalReferenceDelete = async externalReferenceId => {
  return deleteEntityById(externalReferenceId);
};
export const externalReferenceAddRelation = (user, externalReferenceId, input) => {
  return createRelation(externalReferenceId, input).then(relationData => {
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const externalReferenceDeleteRelation = (user, externalReferenceId, relationId) => {
  deleteRelationById(externalReferenceId, relationId).then(relationData => {
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const externalReferenceEditField = (user, externalReferenceId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(externalReferenceId, input, wTx);
  }).then(async () => {
    const externalReference = await loadEntityById(externalReferenceId);
    return notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user);
  });
};

export const externalReferenceCleanContext = (user, externalReferenceId) => {
  delEditContext(user, externalReferenceId);
  return loadEntityById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};
export const externalReferenceEditContext = (user, externalReferenceId, input) => {
  setEditContext(user, externalReferenceId, input);
  return loadEntityById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};
