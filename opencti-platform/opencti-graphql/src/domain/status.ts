import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import {
  createEntity,
  deleteElementById, internalDeleteElementById,
  updateAttribute
} from '../database/middleware';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../database/middleware-loader';
import { findById as findSubTypeById } from './subType';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import type {
  EditInput,
  QueryStatusesArgs,
  QueryStatusTemplatesArgs,
  StatusAddInput,
  StatusTemplate,
  StatusTemplateAddInput,
} from '../generated/graphql';
import { EditContext, OrderingMode, StatusFilter, StatusOrdering } from '../generated/graphql';
import type { AuthContext, AuthUser } from '../types/user';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import type { BasicStoreEntity, BasicWorkflowStatus } from '../types/store';
import { getEntitiesFromCache } from '../database/cache';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { elCount } from '../database/engine';

export const findTemplateById = (context: AuthContext, user: AuthUser, statusTemplateId: string): StatusTemplate => {
  return storeLoadById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE) as unknown as StatusTemplate;
};
export const findAllTemplates = async (context: AuthContext, user: AuthUser, args: QueryStatusTemplatesArgs) => {
  return listEntitiesPaginated<BasicStoreEntity>(context, user, [ENTITY_TYPE_STATUS_TEMPLATE], args);
};
export const findById = async (context: AuthContext, user: AuthUser, statusId: string): Promise<BasicWorkflowStatus> => {
  const platformStatuses = await getEntitiesFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  const basicWorkflowStatus = platformStatuses.find((status) => status.id === statusId);
  return basicWorkflowStatus ?? await storeLoadById(context, user, statusId, ENTITY_TYPE_STATUS) as unknown as BasicWorkflowStatus;
};
export const findByType = async (context: AuthContext, user: AuthUser, statusType: string): Promise<Array<BasicWorkflowStatus>> => {
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
    filters: [{ key: [StatusFilter.Type], values: [type] }],
  };
  return findAll(context, user, args);
};
export const createStatusTemplate = async (context: AuthContext, user: AuthUser, input: StatusTemplateAddInput) => {
  const data = await createEntity(context, user, input, ENTITY_TYPE_STATUS_TEMPLATE);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, data, user);
};
export const createStatus = async (context: AuthContext, user: AuthUser, subTypeId: string, input: StatusAddInput) => {
  const data = await createEntity(context, user, { type: subTypeId, ...input }, ENTITY_TYPE_STATUS);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, data, user);
};
export const statusEditField = async (context: AuthContext, user: AuthUser, subTypeId: string, statusId: string, input: EditInput) => {
  const { element } = await updateAttribute(context, user, statusId, ENTITY_TYPE_STATUS, input);
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  return findSubTypeById(subTypeId);
};
export const statusTemplateEditField = async (context: AuthContext, user: AuthUser, statusTemplateId: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE, input);
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};
export const statusDelete = async (context: AuthContext, user: AuthUser, subTypeId: string, statusId: string) => {
  const { element: deleted } = await internalDeleteElementById(context, user, statusId);
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, deleted, user);
  return findSubTypeById(subTypeId);
};
export const statusTemplateDelete = async (context: AuthContext, user: AuthUser, statusTemplateId: string) => {
  const filters = [{ key: ['template_id'], values: [statusTemplateId] }];
  const result = await listAllEntities(context, user, [ENTITY_TYPE_STATUS], { filters, connectionFormat: false });
  await Promise.all(result.map((status) => internalDeleteElementById(context, user, status.id)
    .then(({ element }) => notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user))));
  return deleteElementById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE);
};
export const statusTemplateEditContext = async (context: AuthContext, user: AuthUser, statusTemplateId: string, input: EditContext) => {
  await setEditContext(user, statusTemplateId, input);
  // eslint-disable-next-line max-len
  return storeLoadById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE).then((statusTemplate) => notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, statusTemplate, user));
};
export const statusTemplateCleanContext = async (context: AuthContext, user: AuthUser, statusTemplateId: string) => {
  await delEditContext(user, statusTemplateId);
  // eslint-disable-next-line max-len
  return storeLoadById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE).then((statusTemplate) => notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, statusTemplate, user));
};
export const statusTemplateUsagesNumber = async (context: AuthContext, user: AuthUser, statusTemplateId: string) => {
  const filters = [{ key: ['template_id'], values: [statusTemplateId] }];
  const options = {
    filters,
    types: [ENTITY_TYPE_STATUS],
  };
  const result = elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, options);
  const count = await Promise.all([result]);
  return count[0];
};
