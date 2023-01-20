import { elIndex, elPaginate } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_DATA_INDICES, READ_DATA_INDICES_WITHOUT_INFERRED, } from '../database/utils';
import { ENTITY_TYPE_TASK } from '../schema/internalObject';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { convertFiltersFrontendFormat, GlobalFilters, TYPE_FILTER } from '../utils/filtering';
import { SYSTEM_USER } from '../utils/access';
import { RULE_PREFIX } from '../schema/general';
import { buildEntityFilters, listEntities, storeLoadById } from '../database/middleware-loader';
import { checkActionValidity, createDefaultTask } from './task-common';

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
  return storeLoadById(context, user, taskId, ENTITY_TYPE_TASK);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_TASK], args);
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
        types.push(...values.map((v) => v.id));
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
    types.push('Stix-Domain-Object');
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
  await elIndex(INDEX_INTERNAL_OBJECTS, queryTask);
  return queryTask;
};

export const deleteTask = async (context, user, taskId) => {
  await deleteElementById(context, user, taskId, ENTITY_TYPE_TASK);
  return taskId;
};

export const updateTask = async (context, taskId, patch) => {
  await patchAttribute(context, SYSTEM_USER, taskId, ENTITY_TYPE_TASK, patch);
};
