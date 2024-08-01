import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { elIndex, elPaginate } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_DATA_INDICES } from '../database/utils';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_INTERNAL_FILE } from '../schema/internalObject';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../utils/access';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, RULE_PREFIX } from '../schema/general';
import { buildEntityFilters, listEntities, storeLoadById } from '../database/middleware-loader';
import { checkActionValidity, createDefaultTask, TASK_TYPE_QUERY, TASK_TYPE_RULE } from './backgroundTask-common';
import { publishUserAction } from '../listener/UserActionListener';
import { ForbiddenAccess } from '../config/errors';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_NOTIFICATION } from '../modules/notification/notification-types';
import { ENTITY_TYPE_CASE_TEMPLATE } from '../modules/case/case-template/case-template-types';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_LABEL } from '../schema/stixMetaObject';
import { ENTITY_TYPE_DELETE_OPERATION } from '../modules/deleteOperation/deleteOperation-types';
import { BackgroundTaskScope, FilterMode } from '../generated/graphql';
import { findAll as findAllWorkspaces } from '../modules/workspace/workspace-domain';
import { addFilter } from '../utils/filtering/filtering-utils';

export const DEFAULT_ALLOWED_TASK_ENTITY_TYPES = [
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  STIX_SIGHTING_RELATIONSHIP,
  ENTITY_TYPE_VOCABULARY,
  ENTITY_TYPE_NOTIFICATION,
  ENTITY_TYPE_CASE_TEMPLATE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_DELETE_OPERATION,
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_INTERNAL_FILE,
];

export const MAX_TASK_ELEMENTS = 500;

export const ACTION_TYPE_ADD = 'ADD';
export const ACTION_TYPE_REMOVE = 'REMOVE';
export const ACTION_TYPE_REPLACE = 'REPLACE';
export const ACTION_TYPE_MERGE = 'MERGE';
export const ACTION_TYPE_PROMOTE = 'PROMOTE';
export const ACTION_TYPE_ENRICHMENT = 'ENRICHMENT';
export const ACTION_TYPE_RULE_APPLY = 'RULE_APPLY';
export const ACTION_TYPE_RULE_CLEAR = 'RULE_CLEAR';
export const ACTION_TYPE_RULE_ELEMENT_RESCAN = 'RULE_ELEMENT_RESCAN';

export const findById = async (context, user, taskId) => {
  return storeLoadById(context, user, taskId, ENTITY_TYPE_BACKGROUND_TASK);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_BACKGROUND_TASK], args);
};

const buildQueryFilters = async (context, user, filters, search, taskPosition, scope) => {
  let inputFilters = filters ? JSON.parse(filters) : undefined;
  if (scope === BackgroundTaskScope.Import) {
    const entityIdFilters = inputFilters.filters.findIndex(({ key }) => key.includes('entity_id'));
    const fileIdFilters = inputFilters.filters.findIndex(({ key }) => key.includes('file_id'));
    if (entityIdFilters >= 0) {
      inputFilters.filters[entityIdFilters] = {
        ...inputFilters.filters[entityIdFilters],
        key: ['metaData.entity_id'],
      };
    }
    if (fileIdFilters >= 0) {
      inputFilters.filters[fileIdFilters] = {
        ...inputFilters.filters[fileIdFilters],
        key: ['internal_id'],
      };
    }
  }
  let types = DEFAULT_ALLOWED_TASK_ENTITY_TYPES;
  if (scope === BackgroundTaskScope.PublicDashboard) {
    const dashboards = await findAllWorkspaces(
      context,
      user,
      {
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['type'], values: ['dashboard'] }],
          filterGroups: []
        }
      }
    );
    const dashboardIds = dashboards.edges.map((n) => (n.node.id));
    inputFilters = addFilter(inputFilters, 'dashboard_id', dashboardIds);
    types = [ENTITY_TYPE_PUBLIC_DASHBOARD];
  } else if (scope === BackgroundTaskScope.Dashboard || scope === BackgroundTaskScope.Investigation) {
    types = [ENTITY_TYPE_WORKSPACE];
  }
  // Construct filters
  return {
    types,
    first: MAX_TASK_ELEMENTS,
    orderMode: 'desc',
    orderBy: 'created_at',
    after: taskPosition,
    filters: inputFilters,
    search: search && search.length > 0 ? search : null,
  };
};
export const executeTaskQuery = async (context, user, filters, search, scope, start = null) => {
  const options = await buildQueryFilters(context, user, filters, search, start, scope);
  return elPaginate(context, user, READ_DATA_INDICES, options);
};

export const createRuleTask = async (context, user, ruleDefinition, input) => {
  const { rule, enable } = input;
  const { scan } = ruleDefinition;
  const opts = enable
    ? buildEntityFilters(scan.types, scan)
    : { filters: {
      mode: 'and',
      filters: [{ key: `${RULE_PREFIX}${rule}`, values: ['EXISTS'] }],
      filterGroups: [],
    }
    };
  const queryData = await elPaginate(context, user, READ_DATA_INDICES, { ...opts, first: 1 });
  const countExpected = queryData.pageInfo.globalCount;
  const task = createDefaultTask(user, input, TASK_TYPE_RULE, countExpected);
  const ruleTask = { ...task, rule, enable };
  await elIndex(INDEX_INTERNAL_OBJECTS, ruleTask);
  return ruleTask;
};

export const createQueryTask = async (context, user, input) => {
  const { actions, filters, excluded_ids = [], search = null, scope } = input;
  await checkActionValidity(context, user, input, scope, TASK_TYPE_QUERY);
  const queryData = await executeTaskQuery(context, user, filters, search, scope);
  const countExpected = queryData.pageInfo.globalCount - excluded_ids.length;
  const task = createDefaultTask(user, input, TASK_TYPE_QUERY, countExpected, scope);
  const queryTask = {
    ...task,
    actions,
    task_filters: filters,
    task_search: search,
    task_excluded_ids: excluded_ids,
  };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: 'creates `background task`',
    context_data: { entity_type: ENTITY_TYPE_BACKGROUND_TASK, input: queryTask }
  });
  await elIndex(INDEX_INTERNAL_OBJECTS, queryTask);
  return queryTask;
};

export const deleteRuleTasks = async (context, user, ruleId) => {
  const tasksFilters = {
    mode: 'and',
    filters: [{ key: 'type', values: ['RULE'] }, { key: 'rule', values: [ruleId] }],
    filterGroups: [],
  };
  const args = { filters: tasksFilters, connectionFormat: false };
  const tasks = await listEntities(context, user, [ENTITY_TYPE_BACKGROUND_TASK], args);
  await Promise.all(tasks.map((t) => deleteElementById(context, user, t.internal_id, ENTITY_TYPE_BACKGROUND_TASK)));
};

export const deleteTask = async (context, user, taskId) => {
  // check if the user has the right to delete the task
  const taskToDelete = await findById(context, SYSTEM_USER, taskId);
  if (taskToDelete && getUserAccessRight(user, taskToDelete) !== MEMBER_ACCESS_RIGHT_ADMIN) {
    throw ForbiddenAccess();
  }
  // delete the task
  const deleted = await deleteElementById(context, user, taskId, ENTITY_TYPE_BACKGROUND_TASK);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: 'deletes `background task`',
    context_data: { id: deleted.id, entity_type: ENTITY_TYPE_BACKGROUND_TASK, input: deleted }
  });
  return taskId;
};

export const updateTask = async (context, taskId, patch) => {
  await patchAttribute(context, SYSTEM_USER, taskId, ENTITY_TYPE_BACKGROUND_TASK, patch);
};
