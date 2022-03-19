import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import { deleteElementById, loadById, updateAttribute } from '../database/middleware';
import { listEntities } from '../database/repository';
import { findById as findSubTypeById } from './subType';
import { getParentTypes } from '../schema/schemaUtils';
import { BASE_TYPE_ENTITY } from '../schema/general';
import type {
  Status,
  StatusTemplate,
  QueryStatusTemplatesArgs,
  QueryStatusesArgs,
  EditInput,
} from '../generated/graphql';
import { OrderingMode, StatusFilter, StatusOrdering } from '../generated/graphql';

export const findTemplateById = (user: AuthUser, statusTemplateId: string): StatusTemplate => {
  return loadById(user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE) as unknown as StatusTemplate;
};
export const findAllTemplates = async (user: AuthUser, args: QueryStatusTemplatesArgs) => {
  return listEntities(user, [ENTITY_TYPE_STATUS_TEMPLATE], args);
};
export const findById = (user: AuthUser, statusId: string): Status => {
  return loadById(user, statusId, ENTITY_TYPE_STATUS) as unknown as Status;
};
export const findAll = (user: AuthUser, args: QueryStatusesArgs) => {
  return listEntities(user, [ENTITY_TYPE_STATUS], args);
};
export const getTypeStatuses = async (user: AuthUser, type: string) => {
  const args = {
    orderBy: StatusOrdering.Order,
    orderMode: OrderingMode.Asc,
    filters: [{ key: StatusFilter.Type, values: [type] }],
  };
  return findAll(user, args);
};
export const createStatusTemplate = async (user: AuthUser, input: StatusTemplateInput) => {
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
export const createStatus = async (user: AuthUser, subTypeId: string, input: StatusInput, returnStatus = false) => {
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
export const statusEditField = async (user: AuthUser, subTypeId: string, statusId: string, input: EditInput) => {
  await updateAttribute(user, statusId, ENTITY_TYPE_STATUS, input);
  return findSubTypeById(subTypeId);
};
export const statusDelete = async (user: AuthUser, subTypeId: string, statusId: string) => {
  await deleteElementById(user, statusId, ENTITY_TYPE_STATUS);
  return findSubTypeById(subTypeId);
};
