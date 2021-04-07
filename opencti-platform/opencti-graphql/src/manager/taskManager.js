/* eslint-disable camelcase */
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import * as R from 'ramda';
import { lockResource } from '../database/redis';
import {
  executeTaskQuery,
  findAll,
  MAX_TASK_ELEMENTS,
  TASK_TYPE_LIST,
  TASK_TYPE_QUERY,
  updateTask,
} from '../domain/task';
import conf, { logger } from '../config/conf';
import { resolveUserById, SYSTEM_USER } from '../domain/user';
import { deleteElementById, internalLoadById } from '../database/middleware';
import { now } from '../utils/format';

// Expired manager responsible to monitor expired elements
// In order to change the revoked attribute to true
// Each API will start is manager.
// When manager do it scan it take a lock and periodically renew it until the job is done.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('task_scheduler:interval');
const TASK_MANAGER_KEY = conf.get('task_scheduler:lock_key');

const ACTION_TYPE_DELETE = 'DELETE';
const ACTION_TYPE_ADD = 'ADD';
const ACTION_TYPE_REMOVE = 'REMOVE';
const ACTION_TYPE_REPLACE = 'REPLACE';

const findTaskToExecute = async () => {
  const tasks = await findAll(SYSTEM_USER, {
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
  const expectedNumber = data.pageInfo.globalCount;
  const elements = data.edges;
  // Apply the actions for each element
  for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
    const element = elements[elementIndex];
    processingElements.push({ element: element.node, actions, next: element.cursor });
  }
  return { processingElements, expectedNumber };
};
const computeListTaskElements = async (user, task) => {
  const { actions, task_position, task_ids } = task;
  const processingElements = [];
  const expectedNumber = task_ids.length;
  const isUndefinedPosition = R.isNil(task_position) || R.isEmpty(task_position);
  const startIndex = isUndefinedPosition ? 0 : task_ids.findIndex(task_position);
  const ids = R.take(MAX_TASK_ELEMENTS, task_ids.slice(startIndex));
  for (let elementId = 0; elementId < ids.length; elementId += 1) {
    const elementToResolve = task_ids[elementId];
    const element = await internalLoadById(user, elementToResolve);
    processingElements.push({ element, actions, next: element.id });
  }
  return { processingElements, expectedNumber };
};
const executeProcessing = async (user, processingElements) => {
  const errors = [];
  for (let index = 0; index < processingElements.length; index += 1) {
    const { element, actions } = processingElements[index];
    try {
      for (let actionIndex = 0; actionIndex < actions.length; actionIndex += 1) {
        // eslint-disable-next-line no-unused-vars
        const { type, context } = actions[actionIndex];
        if (type === ACTION_TYPE_DELETE) {
          await deleteElementById(user, element.internal_id, element.entity_type);
          // You cant have multiple actions on deletion, just stopping the loop.
          break;
        }
        if (type === ACTION_TYPE_ADD) {
          // TODO
        }
        if (type === ACTION_TYPE_REMOVE) {
          // TODO
        }
        if (type === ACTION_TYPE_REPLACE) {
          // TODO
        }
      }
    } catch (err) {
      errors.push({ id: element.id, message: err.message });
    }
  }
  return errors;
};

const taskHandler = async () => {
  logger.info('[OPENCTI] Running Expiration manager');
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([TASK_MANAGER_KEY]);
    logger.info('[OPENCTI] Task manager lock acquired');
    const task = await findTaskToExecute();
    // region Task checking
    if (!task) {
      // Nothing to execute.
      return;
    }
    const isQueryTask = task.type === TASK_TYPE_QUERY;
    const isListTask = task.type === TASK_TYPE_LIST;
    if (!isQueryTask && !isListTask) {
      logger.error(`[OPENCTI] Task manager can't process ${task.type} type`);
      return;
    }
    // endregion
    // Fetch the user responsible for the task
    let expectedNumber = 0;
    const user = await resolveUserById(task.initiator_id);
    let processingElements;
    if (isQueryTask) {
      const data = await computeQueryTaskElements(user, task);
      expectedNumber = data.expectedNumber;
      processingElements = data.processingElements;
    }
    if (isListTask) {
      const data = await computeListTaskElements(user, task);
      expectedNumber = data.expectedNumber;
      processingElements = data.processingElements;
    }
    // Process the elements
    await executeProcessing(user, processingElements);
    // Update the task
    // Get the last element processed and update task_position+ task_processed_number
    const processedNumber = task.task_processed_number + processingElements.length;
    const patch = {
      task_position: R.last(processingElements).next,
      task_processed_number: processedNumber,
      task_expected_number: expectedNumber,
      last_execution_date: now(),
      completed: processingElements.length < MAX_TASK_ELEMENTS,
    };
    await updateTask(task.id, patch);
    console.log(patch);
  } catch (e) {
    // We dont care about failing to get the lock.
    logger.info('[OPENCTI] Task manager already in progress by another API');
  } finally {
    logger.info('[OPENCTI] Task manager done');
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
