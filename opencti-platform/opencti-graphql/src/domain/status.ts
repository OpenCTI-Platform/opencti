import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import * as R from 'ramda';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import { createEntity, deleteElementById, internalDeleteElementById, updateAttribute } from '../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById, storeLoadByIds } from '../database/middleware-loader';
import { findById as findSubTypeById } from './subType';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import {
  type EditContext,
  type EditInput,
  FilterMode,
  OrderingMode,
  type QueryStatusesArgs,
  type QueryStatusTemplatesArgs,
  type QueryStatusTemplatesByStatusScopeArgs,
  type StatusAddInput,
  StatusOrdering,
  StatusScope,
  type StatusTemplate,
  type StatusTemplateAddInput,
} from '../generated/graphql';
import type { AuthContext, AuthUser } from '../types/user';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import type { BasicStoreEntity, BasicWorkflowStatus, StoreEntity } from '../types/store';
import { getEntitiesListFromCache } from '../database/cache';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { elCount } from '../database/engine';
import { publishUserAction } from '../listener/UserActionListener';
import { validateSetting } from '../modules/entitySetting/entitySetting-validators';
import { telemetry } from '../config/tracing';

export const findTemplateById = (context: AuthContext, user: AuthUser, statusTemplateId: string): StatusTemplate => {
  return storeLoadById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE) as unknown as StatusTemplate;
};
export const findTemplatePaginated = async (context: AuthContext, user: AuthUser, args: QueryStatusTemplatesArgs) => {
  return pageEntitiesConnection<BasicStoreEntity>(context, user, [ENTITY_TYPE_STATUS_TEMPLATE], args);
};
export const findAllTemplatesByStatusScope = async (context: AuthContext, user: AuthUser, args: QueryStatusTemplatesByStatusScopeArgs) => {
  const platformStatuses = await getEntitiesListFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  const allStatusesByScope = platformStatuses.filter((status) => status.scope === args.scope);
  const templateIds = allStatusesByScope.map((status) => status.template_id);
  return storeLoadByIds<BasicWorkflowStatus>(context, user, templateIds, ENTITY_TYPE_STATUS_TEMPLATE);
};
export const findById = async (context: AuthContext, user: AuthUser, statusId: string): Promise<BasicWorkflowStatus> => {
  const platformStatuses = await getEntitiesListFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  const basicWorkflowStatus = platformStatuses.find((status) => status.id === statusId);
  return basicWorkflowStatus ?? await storeLoadById(context, user, statusId, ENTITY_TYPE_STATUS) as unknown as BasicWorkflowStatus;
};
export const findByType = async (context: AuthContext, user: AuthUser, statusType: string): Promise<Array<BasicWorkflowStatus>> => {
  const platformStatuses = await getEntitiesListFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  return platformStatuses.filter((status) => status.type === statusType);
};
export const findStatusPaginated = (context: AuthContext, user: AuthUser, args: QueryStatusesArgs) => {
  return pageEntitiesConnection<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], args);
};
export const getTypeStatuses = async (context: AuthContext, user: AuthUser, type: string) => {
  const getTypeStatusesFn = async () => {
    const args = {
      orderBy: StatusOrdering.Order,
      orderMode: OrderingMode.Asc,
      filters: {
        mode: 'and' as FilterMode,
        filters: [{ key: ['type'], values: [type] }],
        filterGroups: [],
      },
    };
    return findStatusPaginated(context, user, args);
  };
  return telemetry(context, user, 'QUERY type statuses', {
    [SEMATTRS_DB_NAME]: 'statuses_domain',
    [SEMATTRS_DB_OPERATION]: 'read',
  }, getTypeStatusesFn);
};

// For now, we duplicate the method, there is a strange behavior with the batch loading.
// For some reason when scope is an args of statuses and is called twice in the same graphQL query, first scope is applied for all.
export const batchRequestAccessStatusesByType = async (context: AuthContext, user: AuthUser, types: string[]) => {
  const batchStatusesByTypeFn = async () => {
    const argsFilter = {
      orderBy: StatusOrdering.Order,
      orderMode: OrderingMode.Asc,
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['type'], values: types }, { key: ['scope'], values: [StatusScope.RequestAccess] }],
        filterGroups: [],
      },
    };
    const statuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], argsFilter);
    const statusesGrouped = R.groupBy((e) => e.type, statuses);
    return types.map((type) => statusesGrouped[type] || []);
  };
  return telemetry(context, user, 'BATCH type statuses', {
    [SEMATTRS_DB_NAME]: 'statuses_domain',
    [SEMATTRS_DB_OPERATION]: 'read',
  }, batchStatusesByTypeFn);
};

export const batchGlobalStatusesByType = async (context: AuthContext, user: AuthUser, types: string[]) => {
  const batchStatusesByTypeFn = async () => {
    const args = {
      orderBy: StatusOrdering.Order,
      orderMode: OrderingMode.Asc,
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['type'], values: types }, { key: ['scope'], values: [StatusScope.Global] }],
        filterGroups: [],
      },
    };
    const statuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], args);
    const statusesGrouped = R.groupBy((e) => e.type, statuses);
    return types.map((type) => statusesGrouped[type] || []);
  };
  return telemetry(context, user, 'BATCH type statuses', {
    [SEMATTRS_DB_NAME]: 'statuses_domain',
    [SEMATTRS_DB_OPERATION]: 'read',
  }, batchStatusesByTypeFn);
};
export const createStatusTemplate = async (context: AuthContext, user: AuthUser, input: StatusTemplateAddInput) => {
  const { element } = await createEntity(context, user, input, ENTITY_TYPE_STATUS_TEMPLATE, { complete: true });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates status template \`${element.name}\``,
    context_data: { id: element.id, entity_type: ENTITY_TYPE_STATUS_TEMPLATE, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, element, user);
};

export const createStatus = async (context: AuthContext, user: AuthUser, subTypeId: string, input: StatusAddInput) => {
  validateSetting(subTypeId, 'workflow_configuration');
  const data = await createEntity(context, user, { type: subTypeId, ...input }, ENTITY_TYPE_STATUS);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`workflow\` for entity setting \`${subTypeId}\``,
    context_data: { id: data.id, entity_type: subTypeId, input: { type: subTypeId, ...input } },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, data, user);
};
export const statusEditField = async (context: AuthContext, user: AuthUser, subTypeId: string, statusId: string, input: EditInput[]) => {
  validateSetting(subTypeId, 'workflow_configuration');
  const { element } = await updateAttribute(context, user, statusId, ENTITY_TYPE_STATUS, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`workflow\` for entity setting \`${subTypeId}\``,
    context_data: { id: element.id, entity_type: subTypeId, input: { type: subTypeId, ...input } },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  return findSubTypeById(subTypeId);
};
export const statusTemplateEditField = async (context: AuthContext, user: AuthUser, statusTemplateId: string, input: EditInput[]) => {
  const { element } = await updateAttribute<StoreEntity>(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for status template \`${element.name}\``,
    context_data: { id: statusTemplateId, entity_type: ENTITY_TYPE_STATUS_TEMPLATE, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
};
export const statusDelete = async (context: AuthContext, user: AuthUser, subTypeId: string, statusId: string) => {
  validateSetting(subTypeId, 'workflow_configuration');
  const { element: deleted } = await internalDeleteElementById(context, user, statusId, ENTITY_TYPE_STATUS);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`workflow\` for entity setting \`${subTypeId}\``,
    context_data: { id: statusId, entity_type: subTypeId, input: { id: subTypeId } },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, deleted, user);
  return findSubTypeById(subTypeId);
};
export const statusTemplateDelete = async (context: AuthContext, user: AuthUser, statusTemplateId: string) => {
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['template_id'], values: [statusTemplateId] }],
    filterGroups: [],
  };
  const result = await fullEntitiesList(context, user, [ENTITY_TYPE_STATUS], { filters });
  await Promise.all(result.map((status) => internalDeleteElementById(context, user, status.id, ENTITY_TYPE_STATUS)
    .then(({ element }) => notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user))));
  const deleted = await deleteElementById<StoreEntity>(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes status template \`${deleted.name}\``,
    context_data: { id: statusTemplateId, entity_type: ENTITY_TYPE_STATUS_TEMPLATE, input: deleted },
  });
  return statusTemplateId;
};
export const statusTemplateEditContext = async (context: AuthContext, user: AuthUser, statusTemplateId: string, input: EditContext) => {
  await setEditContext(user, statusTemplateId, input);

  return storeLoadById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE).then((statusTemplate) => {
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, statusTemplate, user);
  });
};
export const statusTemplateCleanContext = async (context: AuthContext, user: AuthUser, statusTemplateId: string) => {
  await delEditContext(user, statusTemplateId);

  return storeLoadById(context, user, statusTemplateId, ENTITY_TYPE_STATUS_TEMPLATE).then((statusTemplate) => {
    return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, statusTemplate, user);
  });
};
export const statusTemplateUsagesNumber = async (context: AuthContext, user: AuthUser, statusTemplateId: string) => {
  const filters = {
    mode: 'and',
    filters: [{ key: ['template_id'], values: [statusTemplateId] }],
    filterGroups: [],
  };
  const options = { filters, types: [ENTITY_TYPE_STATUS] };
  const result = elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, options);
  const count = await Promise.all([result]);
  return count[0];
};

export const isGlobalWorkflowEnabled = async (context: AuthContext, user: AuthUser, subTypeId: string) => {
  const entityStatusFromCache = await findByType(context, user, subTypeId);
  const globalStatuses = entityStatusFromCache.filter((status) => status.scope === StatusScope.Global);
  return globalStatuses.length > 0;
};
