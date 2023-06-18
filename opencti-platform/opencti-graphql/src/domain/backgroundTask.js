import { elIndex, elPaginate } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_DATA_INDICES, READ_DATA_INDICES_WITHOUT_INFERRED, } from '../database/utils';
import { ENTITY_TYPE_BACKGROUND_TASK } from '../schema/internalObject';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { convertFiltersFrontendFormat, GlobalFilters, TYPE_FILTER } from '../utils/filtering';
import { SYSTEM_USER } from '../utils/access';
import { ABSTRACT_STIX_DOMAIN_OBJECT, RULE_PREFIX } from '../schema/general';
import { buildEntityFilters, listEntities, storeLoadById } from '../database/middleware-loader';
import { checkActionValidity, createDefaultTask, isTaskEnabledEntity } from './backgroundTask-common';
import { publishUserAction } from '../listener/UserActionListener';

export const MAX_TASK_ELEMENTS = 500;

export const TASK_TYPE_QUERY = 'QUERY';
export const TASK_TYPE_RULE = 'RULE';

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

const buildQueryFilters = async (context, rawFilters, search, taskPosition) => {
  const types = [];
  const queryFilters = [];
  const filters = rawFilters ? JSON.parse(rawFilters) : undefined;
  if (filters) {
    const adaptedFilters = await convertFiltersFrontendFormat(context, filters);
    const nestedFrom = [];
    const nestedTo = [];
    let nestedFromRole = false;
    let nestedToRole = false;
    for (let index = 0; index < adaptedFilters.length; index += 1) {
      const { key, operator, values } = adaptedFilters[index];
      if (key === TYPE_FILTER) {
        // filter types to keep only the ones that can be handled by background tasks
        const filteredTypes = values.filter((v) => isTaskEnabledEntity(v.id)).map((v) => v.id);
        types.push(...filteredTypes);
      } else if (key === 'elementId') {
        const nestedElement = [{ key: 'internal_id', values: values.map((v) => v.id) }];
        queryFilters.push({ key: 'connections', nested: nestedElement });
      } else if (key === 'elementWithTargetTypes') {
        const nestedElementTypes = [{ key: 'types', values: values.map((v) => v.id) }];
        queryFilters.push({ key: 'connections', nested: nestedElementTypes });
      } else if (key === 'fromId') {
        nestedFrom.push({ key: 'internal_id', values: values.map((v) => v.id) });
        nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
        nestedFromRole = true;
      } else if (key === 'fromTypes') {
        nestedFrom.push({ key: 'types', values: values.map((v) => v.id) });
        if (!nestedFromRole) {
          nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
        }
      } else if (key === 'toId') {
        nestedTo.push({ key: 'internal_id', values: values.map((v) => v.id) });
        nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
        nestedToRole = true;
      } else if (key === 'toTypes') {
        nestedTo.push({ key: 'types', values: values.map((v) => v.id) });
        if (!nestedToRole) {
          nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
        }
      } else {
        queryFilters.push({ key: GlobalFilters[key] || key, values: values.map((v) => v.id), operator });
      }
    }
    if (nestedFrom.length > 0) {
      queryFilters.push({ key: 'connections', nested: nestedFrom });
    }
    if (nestedTo.length > 0) {
      queryFilters.push({ key: 'connections', nested: nestedTo });
    }
  }
  // Avoid empty type which will target internal objects and relationships as well
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_DOMAIN_OBJECT);
  }
  return {
    types,
    first: MAX_TASK_ELEMENTS,
    orderMode: 'asc',
    orderBy: 'created_at',
    after: taskPosition,
    filters: queryFilters,
    search: search && search.length > 0 ? search : null,
  };
};
export const executeTaskQuery = async (context, user, filters, search, start = null) => {
  const options = await buildQueryFilters(context, filters, search, start);
  return elPaginate(context, user, READ_DATA_INDICES_WITHOUT_INFERRED, options);
};

export const createRuleTask = async (context, user, ruleDefinition, input) => {
  const { rule, enable } = input;
  const { scan } = ruleDefinition;
  const opts = enable ? buildEntityFilters(scan) : { filters: [{ key: `${RULE_PREFIX}${rule}`, values: ['EXISTS'] }] };
  const queryData = await elPaginate(context, user, READ_DATA_INDICES, { ...opts, first: 1 });
  const countExpected = queryData.pageInfo.globalCount;
  const task = createDefaultTask(user, input, TASK_TYPE_RULE, countExpected);
  const ruleTask = { ...task, rule, enable };
  await elIndex(INDEX_INTERNAL_OBJECTS, ruleTask);
  return ruleTask;
};

export const createQueryTask = async (context, user, input) => {
  const { actions, filters, excluded_ids = [], search = null } = input;
  checkActionValidity(user, actions);
  const queryData = await executeTaskQuery(context, user, filters, search);
  const countExpected = queryData.pageInfo.globalCount - excluded_ids.length;
  const task = createDefaultTask(user, input, TASK_TYPE_QUERY, countExpected);
  const queryTask = { ...task, actions, task_filters: filters, task_search: search, task_excluded_ids: excluded_ids };
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
  const tasksFilters = [{ key: 'type', values: ['RULE'] }, { key: 'rule', values: [ruleId] }];
  const args = { filters: tasksFilters, connectionFormat: false };
  const tasks = await listEntities(context, user, [ENTITY_TYPE_BACKGROUND_TASK], args);
  await Promise.all(tasks.map((t) => deleteElementById(context, user, t.internal_id, ENTITY_TYPE_BACKGROUND_TASK)));
};

export const deleteTask = async (context, user, taskId) => {
  const deleted = await deleteElementById(context, user, taskId, ENTITY_TYPE_BACKGROUND_TASK);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: 'deletes `background task`',
    context_data: { entity_type: ENTITY_TYPE_BACKGROUND_TASK, input: deleted }
  });
  return taskId;
};

export const updateTask = async (context, taskId, patch) => {
  await patchAttribute(context, SYSTEM_USER, taskId, ENTITY_TYPE_BACKGROUND_TASK, patch);
};
