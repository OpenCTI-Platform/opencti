import * as R from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  topEntitiesOrRelationsList,
  pageEntitiesOrRelationsConnection,
  updateAttribute
} from '../database/middleware';
import { internalLoadById, pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import conf, { BUS_TOPICS } from '../config/conf';
import { FunctionalError, ValidationError } from '../config/errors';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { ABSTRACT_STIX_REF_RELATIONSHIP, BASE_TYPE_ENTITY, buildRefRelationKey } from '../schema/general';
import { isStixRefRelationship, RELATION_EXTERNAL_REFERENCE } from '../schema/stixRefRelationship';
import { isEmptyField } from '../database/utils';
import { BYPASS, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from '../utils/access';
import { stixCoreObjectImportDelete, stixCoreObjectImportPush } from './stixCoreObject';
import { addFilter } from '../utils/filtering/filtering-utils';

export const findById = (context, user, externalReferenceId) => {
  return storeLoadById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
};

export const findReferencesPaginated = (context, user, args) => {
  const filters = addFilter(args.filters, 'base_type', BASE_TYPE_ENTITY);
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_EXTERNAL_REFERENCE], { ...args, filters });
};

const buildFilterForExternalReference = (externalReferenceId, args) => {
  const key = buildRefRelationKey(RELATION_EXTERNAL_REFERENCE);
  let types = ['Stix-Core-Object', 'stix-core-relationship'];
  if (args.types) {
    types = args.types;
  }
  return { types, filters: addFilter(args.filters, key, externalReferenceId) };
};

export const findReferencesForExternalId = async (context, user, externalReferenceId, args) => {
  const { types, filters } = buildFilterForExternalReference(externalReferenceId, args);
  return topEntitiesOrRelationsList(context, user, types, { ...args, filters });
};

export const findReferencesForExternalIdPaginated = async (context, user, externalReferenceId, args) => {
  const { types, filters } = buildFilterForExternalReference(externalReferenceId, args);
  return pageEntitiesOrRelationsConnection(context, user, types, { ...args, filters });
};

export const externalReferenceImportPush = async (context, user, externalReferenceId, file, args = {}) => {
  const entitiesReferences = await findReferencesForExternalId(context, user, externalReferenceId, { types: ['Stix-Domain-Object'], first: 50 });
  const finalArgs = { ...args, importContextEntities: entitiesReferences };
  return stixCoreObjectImportPush(context, user, externalReferenceId, file, finalArgs);
};

export const addExternalReference = async (context, user, externalReference) => {
  const referenceAttachment = conf.get('app:reference_attachment');
  const userCapabilities = R.flatten(user.capabilities.map((c) => c.name.split('_')));
  const isAllowedToByPass = userCapabilities.includes(BYPASS) || userCapabilities.includes(KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE);
  if (!isAllowedToByPass && referenceAttachment && isEmptyField(externalReference.file)) {
    throw ValidationError('You must provide an attachment to create a new external reference', 'file');
  }
  const created = await createEntity(context, user, externalReference, ENTITY_TYPE_EXTERNAL_REFERENCE);
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].ADDED_TOPIC, created, user);
};

export const externalReferenceDelete = async (context, user, externalReferenceId) => {
  const reference = await internalLoadById(context, user, externalReferenceId);
  if (!reference) {
    throw FunctionalError('Cannot delete, External-Reference cannot be found.', { externalReferenceId });
  }
  // If case of linked file reference
  // Call the deletion of file that will also handle the external reference deletion
  if (reference.fileId) {
    await stixCoreObjectImportDelete(context, user, reference.fileId);
  } else {
    await deleteElementById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
  }
  return externalReferenceId;
};

export const externalReferenceAddRelation = async (context, user, externalReferenceId, input) => {
  const externalReference = await storeLoadById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
  if (!externalReference) {
    throw FunctionalError('Cannot add the relation, External Reference cannot be found.', { externalReferenceId });
  }
  if (!isStixRefRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be added through this method, got ${input.relationship_type}.`);
  }
  const finalInput = { ...input, toId: externalReferenceId };
  return createRelation(context, user, finalInput).then((relationData) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, relationData, user);
  });
};

export const externalReferenceDeleteRelation = async (context, user, externalReferenceId, fromId, relationshipType) => {
  const externalReference = await storeLoadById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
  if (!externalReference) {
    throw FunctionalError('Cannot delete the relation, External-Reference cannot be found.', { externalReferenceId });
  }
  if (!isStixRefRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_REF_RELATIONSHIP} can be deleted through this method, got ${input.relationship_type}.`);
  }
  await deleteRelationsByFromAndTo(
    context,
    user,
    fromId,
    externalReferenceId,
    relationshipType,
    ABSTRACT_STIX_REF_RELATIONSHIP
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
};

export const externalReferenceEditField = async (context, user, externalReferenceId, input, opts = {}) => {
  const currentReference = await storeLoadById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE);
  const dataInputs = currentReference.fileId ? input.filter((i) => i.key !== 'url') : input;
  const { element } = await updateAttribute(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE, dataInputs, opts);
  return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, element, user);
};

export const externalReferenceCleanContext = async (context, user, externalReferenceId) => {
  await delEditContext(user, externalReferenceId);
  return storeLoadById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
  });
};

export const externalReferenceEditContext = async (context, user, externalReferenceId, input) => {
  await setEditContext(user, externalReferenceId, input);
  return storeLoadById(context, user, externalReferenceId, ENTITY_TYPE_EXTERNAL_REFERENCE).then((externalReference) => {
    return notify(BUS_TOPICS[ENTITY_TYPE_EXTERNAL_REFERENCE].EDIT_TOPIC, externalReference, user);
  });
};
