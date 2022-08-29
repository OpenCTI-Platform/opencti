import { assoc } from 'ramda';
import * as R from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  internalLoadById,
  listThings,
  storeLoadById,
  paginateAllThings,
  updateAttribute,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import conf, { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess, FunctionalError, ValidationError } from '../config/errors';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { ABSTRACT_STIX_META_RELATIONSHIP, buildRefRelationKey } from '../schema/general';
import { isStixMetaRelationship, RELATION_EXTERNAL_REFERENCE } from '../schema/stixMetaRelationship';
import { isEmptyField } from '../database/utils';
import { BYPASS, BYPASS_REFERENCE } from '../utils/access';

export const findById = (user, externalReferenceId) => {
  return storeLoadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_EXTERNAL_REFERENCE], args);
};

export const references = async (user, externalReferenceId, args) => {
  const key = buildRefRelationKey(RELATION_EXTERNAL_REFERENCE);
  let types = ['Stix-Core-Object', 'stix-core-relationship'];
  if (args.types) {
    types = args.types;
  }
  const filters = [{ key, values: [externalReferenceId] }, ...(args.filters || [])];
  if (args.all) {
    return paginateAllThings(user, types, R.assoc('filters', filters, args));
  }
  return listThings(user, types, R.assoc('filters', filters, args));
};

export const addExternalReference = async (user, externalReference) => {
  const referenceAttachment = conf.get('app:reference_attachment');
  const userCapabilities = R.flatten(user.capabilities.map((c) => c.name.split('_')));
  const isAllowedToByPass = userCapabilities.includes(BYPASS) || userCapabilities.includes(BYPASS_REFERENCE);
  if (!isAllowedToByPass && referenceAttachment && isEmptyField(externalReference.file)) {
    throw ValidationError('file', {
      message: 'You must provide an attachment to create a new external reference',
    });
  }
  const created = await createEntity(user, externalReference, ENTITY_TYPE_EXTERNAL_REFERENCE);
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
  const externalReference = await storeLoadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
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
  return storeLoadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
  });
};

export const externalReferenceEditContext = async (user, externalReferenceId, input) => {
  await setEditContext(user, externalReferenceId, input);
  return storeLoadById(user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
  });
};
