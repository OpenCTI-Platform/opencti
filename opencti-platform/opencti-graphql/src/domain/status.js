import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import { deleteElementById, loadById, updateAttribute } from '../database/middleware';
import { listEntities } from '../database/repository';
import { findById as findSubTypeById } from './subType';
import { getParentTypes } from '../schema/schemaUtils';
import { BASE_TYPE_ENTITY } from '../schema/general';

export const findTemplateById = async (user, statusTemplateId) => {
  return loadById(user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE);
};
export const findAllTemplates = async (user, args) => {
  return listEntities(user, [ENTITY_TYPE_STATUS_TEMPLATE], args);
};
export const findById = async (user, statusId) => {
  return loadById(user, statusId, ENTITY_TYPE_STATUS);
};
export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_STATUS], args);
};
export const getTypeStatuses = async (user, type) => {
  const args = { orderBy: 'order', orderMode: 'asc', filters: [{ key: 'type', values: [type] }] };
  return findAll(user, args);
};
export const createStatusTemplate = async (user, input) => {
  const statusTemplateId = generateInternalId();
  const data = {
    id: statusTemplateId,
    internal_id: statusTemplateId,
    standard_id: generateStandardId(ENTITY_TYPE_STATUS_TEMPLATE, input),
    entity_type: ENTITY_TYPE_STATUS_TEMPLATE,
    parent_types: getParentTypes(ENTITY_TYPE_STATUS_TEMPLATE),
    base_type: BASE_TYPE_ENTITY,
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  return data;
};
export const createStatus = async (user, subTypeId, input, returnStatus = false) => {
  const statusId = generateInternalId();
  const data = {
    id: statusId,
    internal_id: statusId,
    standard_id: generateStandardId(ENTITY_TYPE_STATUS, input),
    entity_type: ENTITY_TYPE_STATUS,
    parent_types: getParentTypes(ENTITY_TYPE_STATUS),
    base_type: BASE_TYPE_ENTITY,
    type: subTypeId,
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, data);
  if (returnStatus) {
    return data;
  }
  return findSubTypeById(subTypeId);
};
export const statusEditField = async (user, subTypeId, statusId, input) => {
  await updateAttribute(user, statusId, ENTITY_TYPE_STATUS, input);
  return findSubTypeById(subTypeId);
};
export const statusDelete = async (user, subTypeId, statusId) => {
  await deleteElementById(user, statusId, ENTITY_TYPE_STATUS);
  return findSubTypeById(subTypeId);
};
