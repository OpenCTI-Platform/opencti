/* eslint-disable camelcase */
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import * as R from 'ramda';
import { lockResource } from '../database/redis';
import {
  ACTION_TYPE_ADD,
  ACTION_TYPE_DELETE,
  ACTION_TYPE_MERGE,
  ACTION_TYPE_REMOVE,
  ACTION_TYPE_REPLACE,
  executeTaskQuery,
  findAll,
  MAX_TASK_ELEMENTS,
  TASK_TYPE_LIST,
  TASK_TYPE_QUERY,
  updateTask,
} from '../domain/task';
import conf, { logApp } from '../config/conf';
import { resolveUserById, SYSTEM_USER } from '../domain/user';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  internalLoadById,
  listAllRelations,
  mergeEntities,
  patchAttribute,
} from '../database/middleware';
import { now } from '../utils/format';
import { INDEX_INTERNAL_OBJECTS, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { elUpdate } from '../database/elasticSearch';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { ABSTRACT_BASIC_RELATIONSHIP } from '../schema/general';

// Task manager responsible to execute long manual tasks
// Each API will start is task manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('task_scheduler:interval');
const TASK_MANAGER_KEY = conf.get('task_scheduler:lock_key');

const ACTION_TYPE_ATTRIBUTE = 'ATTRIBUTE';
const ACTION_TYPE_RELATION = 'RELATION';

const findTaskToExecute = async () => {
  const tasks = await findAll(SYSTEM_USER, {
    connectionFormat: false,
    orderBy: 'created_at',
    orderMode: 'asc',
    limit: 1,
    filters: [{ key: 'completed', values: [false] }],
  });
  if (tasks.length === 0) {
    return null;
  }
  return R.head(tasks);
};
const computeQueryTaskElements = async (user, task) => {
  const { actions, task_position, task_filters } = task;
  const processingElements = [];
  // Fetch the information
  const data = await executeTaskQuery(user, task_filters, task_position);
  // const expectedNumber = data.pageInfo.globalCount;
  const elements = data.edges;
  // Apply the actions for each element
  for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
    const element = elements[elementIndex];
    processingElements.push({ element: element.node, actions, next: element.cursor });
  }
  return processingElements;
};
const computeListTaskElements = async (user, task) => {
  const { actions, task_position, task_ids } = task;
  const processingElements = [];
  // const expectedNumber = task_ids.length;
  const isUndefinedPosition = R.isNil(task_position) || R.isEmpty(task_position);
  const startIndex = isUndefinedPosition ? 0 : task_ids.findIndex(task_position);
  const ids = R.take(MAX_TASK_ELEMENTS, task_ids.slice(startIndex));
  for (let elementId = 0; elementId < ids.length; elementId += 1) {
    const elementToResolve = task_ids[elementId];
    const element = await internalLoadById(user, elementToResolve);
    if (element) {
      processingElements.push({ element, actions, next: element.id });
    }
  }
  return processingElements;
};
const appendTaskErrors = async (taskId, errors) => {
  if (errors.length === 0) {
    return;
  }
  let source = '';
  const params = { received_time: now() };
  for (let index = 0; index < errors.length; index += 1) {
    const error = errors[index];
    source += `ctx._source.errors.add(["timestamp": params.received_time, "id": "${error.id}", "message": "${error.message}"]); `;
  }
  await elUpdate(INDEX_INTERNAL_OBJECTS, taskId, {
    script: { source, lang: 'painless', params },
  });
};

const executeDelete = async (user, element) => {
  await deleteElementById(user, element.internal_id, element.entity_type);
};
const executeAdd = async (user, context, element) => {
  const { field, type: contextType, values } = context;
  if (contextType === ACTION_TYPE_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await createRelation(user, { fromId: element.id, toId: target, relationship_type: field });
    }
  }
  if (contextType === ACTION_TYPE_ATTRIBUTE) {
    const patch = { [field]: values };
    await patchAttribute(user, element.id, element.entity_type, patch, { operation: UPDATE_OPERATION_ADD });
  }
};
const executeRemove = async (user, context, element) => {
  const { field, type: contextType, values } = context;
  if (contextType === ACTION_TYPE_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await deleteRelationsByFromAndTo(user, element.id, target, field, ABSTRACT_BASIC_RELATIONSHIP);
    }
  }
  if (contextType === ACTION_TYPE_ATTRIBUTE) {
    const patch = { [field]: values };
    await patchAttribute(user, element.id, element.entity_type, patch, { operation: UPDATE_OPERATION_REMOVE });
  }
};
const executeReplace = async (user, context, element) => {
  const { field, type: contextType, values } = context;
  if (contextType === ACTION_TYPE_RELATION) {
    // 01 - Delete all relations of the element
    const rels = await listAllRelations(user, field, { fromId: element.id });
    for (let indexRel = 0; indexRel < rels.length; indexRel += 1) {
      const rel = rels[indexRel];
      await deleteElementById(user, rel.id, rel.entity_type);
    }
    // 02 - Create new ones
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await createRelation(user, { fromId: element.id, toId: target, relationship_type: field });
    }
  }
  if (contextType === ACTION_TYPE_ATTRIBUTE) {
    const patch = { [field]: values };
    await patchAttribute(user, element.id, element.entity_type, patch);
  }
};
const executeMerge = async (user, context, element) => {
  const { values } = context;
  await mergeEntities(user, element.internal_id, values);
};

const executeProcessing = async (user, processingElements) => {
  const errors = [];
  for (let index = 0; index < processingElements.length; index += 1) {
    const { element, actions } = processingElements[index];
    try {
      for (let actionIndex = 0; actionIndex < actions.length; actionIndex += 1) {
        const { type, context } = actions[actionIndex];
        if (type === ACTION_TYPE_DELETE) {
          await executeDelete(user, element);
          break; // You cant have multiple actions on deletion, just stopping the loop.
        }
        if (type === ACTION_TYPE_ADD) {
          await executeAdd(user, context, element);
        }
        if (type === ACTION_TYPE_REMOVE) {
          await executeRemove(user, context, element);
        }
        if (type === ACTION_TYPE_REPLACE) {
          await executeReplace(user, context, element);
        }
        if (type === ACTION_TYPE_MERGE) {
          await executeMerge(user, context, element);
        }
      }
    } catch (err) {
      errors.push({ id: element.id, message: err.message });
    }
  }
  return errors;
};

const taskHandler = async () => {
  logApp.debug('[OPENCTI] Running Expiration manager');
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([TASK_MANAGER_KEY]);
    logApp.debug('[OPENCTI] Task manager lock acquired');
    const task = await findTaskToExecute();
    // region Task checking
    if (!task) {
      // Nothing to execute.
      return;
    }
    const isQueryTask = task.type === TASK_TYPE_QUERY;
    const isListTask = task.type === TASK_TYPE_LIST;
    if (!isQueryTask && !isListTask) {
      logApp.error(`[OPENCTI] Task manager can't process ${task.type} type`);
      return;
    }
    // endregion
    // Fetch the user responsible for the task
    const rawUser = await resolveUserById(task.initiator_id);
    const user = { ...rawUser, origin: { user_id: rawUser.id, referer: 'background_task' } };
    let processingElements;
    if (isQueryTask) {
      processingElements = await computeQueryTaskElements(user, task);
    }
    if (isListTask) {
      processingElements = await computeListTaskElements(user, task);
    }
    // Process the elements (empty = end of execution)
    if (processingElements.length > 0) {
      const errors = await executeProcessing(user, processingElements);
      await appendTaskErrors(task.id, errors);
    }
    // Update the task
    // Get the last element processed and update task_position+ task_processed_number
    const processedNumber = task.task_processed_number + processingElements.length;
    const patch = {
      task_position: processingElements.length > 0 ? R.last(processingElements).next : null,
      task_processed_number: processedNumber,
      last_execution_date: now(),
      completed: processingElements.length < MAX_TASK_ELEMENTS,
    };
    await updateTask(task.id, patch);
  } catch (e) {
    // We dont care about failing to get the lock.
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI] Task manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI] Task manager fail to execute', { error: e });
    }
  } finally {
    logApp.debug('[OPENCTI] Task manager done');
    if (lock) await lock.unlock();
  }
};
const initTaskManager = () => {
  let scheduler;
  return {
    start: () => {
      scheduler = setIntervalAsync(async () => {
        await taskHandler();
      }, SCHEDULE_TIME);
    },
    shutdown: () => clearIntervalAsync(scheduler),
  };
};

export default initTaskManager;
