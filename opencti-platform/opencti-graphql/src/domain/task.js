import * as R from 'ramda';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { now } from '../utils/format';
import { elIndex, elPaginate } from '../database/elasticSearch';
import { INDEX_INTERNAL_OBJECTS, READ_STIX_INDICES } from '../database/utils';
import { ENTITY_TYPE_TASK } from '../schema/internalObject';
import { deleteElementById, listEntities, loadById, patchAttribute } from '../database/middleware';
import { SYSTEM_USER } from './user';
import { GlobalFilters } from '../utils/filtering';
import { BYPASS } from '../schema/general';
import { ForbiddenAccess } from '../config/errors';
import { KNOWLEDGE_DELETE } from '../initialization';

export const MAX_TASK_ELEMENTS = 500;

export const TASK_TYPE_QUERY = 'QUERY';
export const TASK_TYPE_LIST = 'LIST';

export const ACTION_TYPE_DELETE = 'DELETE';
export const ACTION_TYPE_ADD = 'ADD';
export const ACTION_TYPE_REMOVE = 'REMOVE';
export const ACTION_TYPE_REPLACE = 'REPLACE';
export const ACTION_TYPE_MERGE = 'MERGE';

const createDefaultTask = (user, input, taskType, taskExpectedNumber) => {
  const taskId = generateInternalId();
  return {
    id: taskId,
    internal_id: taskId,
    standard_id: generateStandardId(ENTITY_TYPE_TASK, input),
    entity_type: ENTITY_TYPE_TASK,
    initiator_id: user.internal_id,
    created_at: now(),
    completed: false,
    // Task related
    type: taskType,
    last_execution_date: null,
    task_position: null, // To mark the progress.
    task_processed_number: 0, // Initial number of processed element
    task_expected_number: taskExpectedNumber, // Expected number of element processed
    errors: [], // To stock the errors
  };
};

export const findById = async (user, taskId) => {
  return loadById(user, taskId, ENTITY_TYPE_TASK);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_TASK], args);
};

const buildQueryFilters = (rawFilters, taskPosition) => {
  const types = [];
  const queryFilters = [];
  const filters = rawFilters ? JSON.parse(rawFilters) : undefined;
  if (filters) {
    const filterEntries = Object.entries(filters);
    for (let index = 0; index < filterEntries.length; index += 1) {
      const [key, val] = filterEntries[index];
      if (key === 'entity_type') {
        types.push(...val.map((v) => v.id));
      } else {
        queryFilters.push({ key: GlobalFilters[key] || key, values: val.map((v) => v.id) });
      }
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
    orderBy: 'internal_id',
    after: taskPosition,
    filters: queryFilters,
  };
};
export const executeTaskQuery = async (user, filters, start = null) => {
  const options = buildQueryFilters(filters, start);
  return elPaginate(user, READ_STIX_INDICES, options);
};

const checkActionValidity = (user, actions) => {
  const askForDeletion = actions.filter((a) => a.type === ACTION_TYPE_DELETE).length > 0;
  if (askForDeletion) {
    // If deletion action available, user need to have the right capability
    const userCapabilities = R.flatten(user.capabilities.map((c) => c.name.split('_')));
    const isAuthorized = userCapabilities.includes(BYPASS) || userCapabilities.includes(KNOWLEDGE_DELETE);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
  }
};

export const createQueryTask = async (user, input) => {
  const { actions, filters } = input;
  checkActionValidity(user, actions);
  const queryData = await executeTaskQuery(user, filters);
  const countExpected = queryData.pageInfo.globalCount;
  const task = createDefaultTask(user, input, TASK_TYPE_QUERY, countExpected);
  const queryTask = { ...task, actions, task_filters: filters };
  await elIndex(INDEX_INTERNAL_OBJECTS, queryTask);
  return queryTask;
};

export const createListTask = async (user, input) => {
  const { actions, ids } = input;
  checkActionValidity(user, actions);
  const task = createDefaultTask(user, input, TASK_TYPE_LIST, ids.length);
  const listTask = { ...task, actions, task_ids: ids };
  await elIndex(INDEX_INTERNAL_OBJECTS, listTask);
  return listTask;
};

export const deleteTask = async (user, taskId) => {
  await deleteElementById(user, taskId, ENTITY_TYPE_TASK);
  return taskId;
};

export const updateTask = async (taskId, patch) => {
  await patchAttribute(SYSTEM_USER, taskId, ENTITY_TYPE_TASK, patch);
};
