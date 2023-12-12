import { elIndex, elPaginate } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_DATA_INDICES, READ_DATA_INDICES_WITHOUT_INFERRED, } from '../database/utils';
import { ENTITY_TYPE_BACKGROUND_TASK } from '../schema/internalObject';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { TYPE_FILTER } from '../utils/filtering/filtering-constants';
import { resolveFilterGroupValuesWithCache } from '../utils/filtering/filtering-resolution';
import { getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../utils/access';
import { ABSTRACT_STIX_DOMAIN_OBJECT, RULE_PREFIX } from '../schema/general';
import { buildEntityFilters, listEntities, storeLoadById } from '../database/middleware-loader';
import { checkActionValidity, createDefaultTask, isTaskEnabledEntity, TASK_TYPE_QUERY, TASK_TYPE_RULE } from './backgroundTask-common';
import { publishUserAction } from '../listener/UserActionListener';
import { ForbiddenAccess } from '../config/errors';

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

const buildQueryFiltersContent = (adaptedFiltersGroup) => {
  if (!adaptedFiltersGroup) {
    return {
      mode: 'and',
      filters: [],
      filterGroups: [],
    };
  }
  const { filters, filterGroups = [] } = adaptedFiltersGroup;
  const queryFilterGroups = [];
  for (let index = 0; index < filterGroups.length; index += 1) {
    const currentGroup = filterGroups[index];
    const filtersResult = buildQueryFiltersContent(currentGroup);
    queryFilterGroups.push(filtersResult);
  }
  const queryFilters = [];
  const nestedFrom = [];
  const nestedTo = [];
  let nestedFromRole = false;
  let nestedToRole = false;
  for (let index = 0; index < filters.length; index += 1) {
    const { key, operator, values, mode } = filters[index];
    if (key === TYPE_FILTER) {
      // filter types to keep only the ones that can be handled by background tasks
      const filteredTypes = values.filter((v) => isTaskEnabledEntity(v));
      queryFilters.push({ key, values: filteredTypes, operator, mode });
    } else if (key === 'elementId') {
      const nestedElement = [{ key: 'internal_id', values }];
      queryFilters.push({ key: 'connections', nested: nestedElement });
    } else if (key === 'elementWithTargetTypes') {
      const nestedElementTypes = [{ key: 'types', values }];
      queryFilters.push({ key: 'connections', nested: nestedElementTypes });
    } else if (key === 'fromId') {
      nestedFrom.push({ key: 'internal_id', values });
      nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
      nestedFromRole = true;
    } else if (key === 'fromTypes') {
      nestedFrom.push({ key: 'types', values });
      if (!nestedFromRole) {
        nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
      }
    } else if (key === 'toId' || key === 'toSightingId') {
      nestedTo.push({ key: 'internal_id', values });
      nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
      nestedToRole = true;
    } else if (key === 'toTypes') {
      nestedTo.push({ key: 'types', values });
      if (!nestedToRole) {
        nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
      }
    } else {
      queryFilters.push({ key, values, operator, mode });
    }
  }
  if (nestedFrom.length > 0) {
    queryFilters.push({ key: 'connections', nested: nestedFrom });
  }
  if (nestedTo.length > 0) {
    queryFilters.push({ key: 'connections', nested: nestedTo });
  }
  return {
    mode: adaptedFiltersGroup.mode,
    filters: queryFilters,
    filterGroups: queryFilterGroups,
  };
};

const buildQueryFilters = async (context, user, rawFilters, search, taskPosition) => {
  // Construct filters
  let adaptedFilterGroup;
  const filters = rawFilters ? JSON.parse(rawFilters) : undefined;
  if (filters) {
    adaptedFilterGroup = await resolveFilterGroupValuesWithCache(context, user, filters);
  }
  const newFilters = buildQueryFiltersContent(adaptedFilterGroup);
  // Avoid empty type which will target internal objects and relationships as well
  const types = newFilters.filters.filter((f) => f.key === TYPE_FILTER)?.values ?? [ABSTRACT_STIX_DOMAIN_OBJECT];
  return {
    types,
    first: MAX_TASK_ELEMENTS,
    orderMode: 'asc',
    orderBy: 'created_at',
    after: taskPosition,
    filters: newFilters,
    search: search && search.length > 0 ? search : null,
  };
};
export const executeTaskQuery = async (context, user, filters, search, start = null) => {
  const options = await buildQueryFilters(context, user, filters, search, start);
  return elPaginate(context, user, READ_DATA_INDICES_WITHOUT_INFERRED, options);
};

export const createRuleTask = async (context, user, ruleDefinition, input) => {
  const { rule, enable } = input;
  const { scan } = ruleDefinition;
  const opts = enable
    ? buildEntityFilters(scan)
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
  const queryData = await executeTaskQuery(context, user, filters, search);
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
