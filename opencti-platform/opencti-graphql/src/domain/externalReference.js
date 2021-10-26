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
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { createWork } from './work';
import { pushToConnector } from '../database/amqp';
import { upload } from '../database/s3';
import { uploadJobImport } from './file';
import { askEnrich } from './enrichment';

export const findById = (user, externalReferenceId) => {
  return loadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_EXTERNAL_REFERENCE], args);
};

export const externalReferenceAskEnrichment = async (user, externalReferenceId, connectorId) => {
  const connector = await loadById(user, connectorId, ENTITY_TYPE_CONNECTOR);
  const work = await createWork(user, connector, 'Manual enrichment', externalReferenceId);
  const message = {
    internal: {
      work_id: work.id, // Related action for history
      applicant_id: user.id, // User asking for the import
    },
    event: {
      entity_id: externalReferenceId,
    },
  };
  await pushToConnector(connector, message);
  return work;
};

export const addExternalReference = async (user, externalReference) => {
  const created = await createEntity(user, externalReference, ENTITY_TYPE_EXTERNAL_REFERENCE);
  if (!created.i_upserted) {
    await askEnrich(user, created.id, ENTITY_TYPE_EXTERNAL_REFERENCE);
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].ADDED_TOPIC, created, user);
};

export const externalReferenceDelete = async (user, externalReferenceId) => {
  return deleteElementById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const externalReferenceAddRelation = async (user, externalReferenceId, input) => {
  const data = await internalLoadById(user, externalReferenceId);
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
  const externalReference = await loadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
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

export const externalReferenceEditField = async (user, externalReferenceId, input, opts = {}) => {
  const { element } = await updateAttribute(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE, input, opts);
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, element, user);
};

export const externalReferenceCleanContext = async (user, externalReferenceId) => {
  await delEditContext(user, externalReferenceId);
  return loadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) =>
    notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditContext = async (user, externalReferenceId, input) => {
  await setEditContext(user, externalReferenceId, input);
  return loadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) =>
    notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceImportPush = async (user, entityId, file) => {
  const entity = await internalLoadById(user, entityId);
  const up = await upload(user, `import/${entity.entity_type}/${entityId}`, file, { entity_id: entityId });
  await uploadJobImport(user, up.id, up.metaData.mimetype, up.metaData.entity_id);
  return up;
};
