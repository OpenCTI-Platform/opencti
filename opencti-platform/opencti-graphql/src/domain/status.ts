import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import { internalDeleteElementById, storeLoadById, updateAttribute } from '../database/middleware';
import { listEntitiesPaginated } from '../database/middleware-loader';
import { findById as findSubTypeById } from './subType';
import { getParentTypes } from '../schema/schemaUtils';
import { ABSTRACT_INTERNAL_OBJECT, BASE_TYPE_ENTITY } from '../schema/general';
import type {
  Status,
  StatusTemplate,
  QueryStatusTemplatesArgs,
  QueryStatusesArgs,
  EditInput,
} from '../generated/graphql';
import { OrderingMode, StatusFilter, StatusOrdering } from '../generated/graphql';
import type { AuthContext, AuthUser } from '../types/user';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import type { BasicStoreEntity, BasicWorkflowStatus } from '../types/store';
import { getEntitiesFromCache } from '../manager/cacheManager';

export const findTemplateById = (context: AuthContext, user: AuthUser, statusTemplateId: string): StatusTemplate => {
  return storeLoadById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE) as unknown as StatusTemplate;
};
export const findAllTemplates = async (context: AuthContext, user: AuthUser, args: QueryStatusTemplatesArgs) => {
  return listEntitiesPaginated<BasicStoreEntity>(context, user, [ENTITY_TYPE_STATUS_TEMPLATE], args);
};
export const findById = async (context: AuthContext, user: AuthUser, statusId: string): Promise<Status> => {
  const platformStatuses = await getEntitiesFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  const basicWorkflowStatus = platformStatuses.find((status) => status.id === statusId);
  return basicWorkflowStatus ?? await storeLoadById(user, statusId, ENTITY_TYPE_STATUS) as unknown as Status;
};
export const findByType = async (context: AuthContext, user: AuthUser, statusType: string): Promise<Array<Status>> => {
  const platformStatuses = await getEntitiesFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  return platformStatuses.filter((status) => status.type === statusType);
};
export const findAll = (context: AuthContext, user: AuthUser, args: QueryStatusesArgs) => {
  return listEntitiesPaginated<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], args);
};
export const getTypeStatuses = async (context: AuthContext, user: AuthUser, type: string) => {
  const args = {
    orderBy: StatusOrdering.Order,
    orderMode: OrderingMode.Asc,
    filters: [{ key: StatusFilter.Type, values: [type] }],
  };
  return findAll(context, user, args);
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
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, data, user);
  if (returnStatus) {
    return data;
  }
  return findSubTypeById(subTypeId);
};
export const statusEditField = async (context: AuthContext, user: AuthUser, subTypeId: string, statusId: string, input: EditInput) => {
  const { element } = await updateAttribute(context, user, statusId, ENTITY_TYPE_STATUS, input);
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  return findSubTypeById(subTypeId);
};
export const statusDelete = async (context: AuthContext, user: AuthUser, subTypeId: string, statusId: string) => {
  const { element: deleted } = await internalDeleteElementById(context, user, statusId);
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, deleted, user);
  return findSubTypeById(subTypeId);
};
