/* eslint-disable camelcase */
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { lockResource, storeCreateEntityEvent } from '../database/redis';
import {
  ACTION_TYPE_ADD,
  ACTION_TYPE_DELETE, ACTION_TYPE_ENRICHMENT,
  ACTION_TYPE_MERGE,
  ACTION_TYPE_PROMOTE,
  ACTION_TYPE_REMOVE,
  ACTION_TYPE_REPLACE,
  ACTION_TYPE_RULE_APPLY,
  ACTION_TYPE_RULE_CLEAR,
  ACTION_TYPE_RULE_ELEMENT_RESCAN,
  executeTaskQuery,
  findAll,
  MAX_TASK_ELEMENTS,
  TASK_TYPE_LIST,
  TASK_TYPE_QUERY,
  TASK_TYPE_RULE,
  updateTask,
} from '../domain/task';
import conf, { logApp } from '../config/conf';
import { resolveUserById } from '../domain/user';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo, internalFindByIds,
  internalLoadById,
  mergeEntities,
  patchAttribute,
  stixLoadById,
  storeLoadByIdWithRefs,
} from '../database/middleware';
import { now } from '../utils/format';
import {
  INDEX_INTERNAL_OBJECTS,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INFERRED,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
} from '../database/utils';
import { elPaginate, elUpdate, ES_MAX_CONCURRENCY } from '../database/engine';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP, RULE_PREFIX } from '../schema/general';
import { SYSTEM_USER } from '../utils/access';
import { buildInternalEvent, rulesApplyHandler, rulesCleanHandler } from './ruleManager';
import { RULE_MANAGER_USER } from '../rules/rules';
import { buildFilters } from '../database/repository';
import { listAllRelations } from '../database/middleware-loader';
import { getActivatedRules, getRule } from '../domain/rules';
import { isStixRelationship } from '../schema/stixRelationship';
import { isStixObject } from '../schema/stixCoreObject';
import { EVENT_TYPE_CREATE } from '../database/rabbitmq';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { promoteObservableToIndicator } from '../domain/stixCyberObservable';
import { promoteIndicatorToObservable } from '../domain/indicator';
import { askElementEnrichmentForConnector } from '../domain/stixCoreObject';

// Task manager responsible to execute long manual tasks
// Each API will start is task manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('task_scheduler:interval');
const TASK_MANAGER_KEY = conf.get('task_scheduler:lock_key');

const ACTION_TYPE_ATTRIBUTE = 'ATTRIBUTE';
const ACTION_TYPE_RELATION = 'RELATION';
const ACTION_TYPE_REVERSED_RELATION = 'REVERSED_RELATION';

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
const computeRuleTaskElements = async (task) => {
  const { task_position, rule, enable } = task;
  const processingElements = [];
  const ruleDefinition = await getRule(rule);
  if (enable) {
    const { scan } = ruleDefinition;
    const options = {
      first: MAX_TASK_ELEMENTS,
      orderMode: 'asc',
      orderBy: 'updated_at',
      after: task_position,
      ...buildFilters(scan),
    };
    const { edges: elements } = await elPaginate(RULE_MANAGER_USER, READ_DATA_INDICES_WITHOUT_INFERRED, options);
    // Apply the actions for each element
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      const actions = [{ type: ACTION_TYPE_RULE_APPLY, context: { rule: ruleDefinition } }];
      processingElements.push({ element: element.node, actions, next: element.cursor });
    }
  } else {
    const filters = [{ key: `${RULE_PREFIX}${rule}`, values: ['EXISTS'] }];
    const options = {
      first: MAX_TASK_ELEMENTS,
      orderMode: 'asc',
      orderBy: 'updated_at',
      after: task_position,
      filters,
    };
    const { edges: elements } = await elPaginate(RULE_MANAGER_USER, READ_DATA_INDICES, options);
    // Apply the actions for each element
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      const actions = [{ type: ACTION_TYPE_RULE_CLEAR, context: { rule: ruleDefinition } }];
      processingElements.push({ element: element.node, actions, next: element.cursor });
    }
  }
  return processingElements;
};
const computeQueryTaskElements = async (user, task) => {
  const { actions, task_position, task_filters, task_search = null, task_excluded_ids = [] } = task;
  const processingElements = [];
  // Fetch the information
  const data = await executeTaskQuery(user, task_filters, task_search, task_position);
  // const expectedNumber = data.pageInfo.globalCount;
  const elements = data.edges;
  // Apply the actions for each element
  for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
    const element = elements[elementIndex];
    if (!task_excluded_ids.includes(element.node.id)) {
      processingElements.push({ element: element.node, actions, next: element.cursor });
    }
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
  if (contextType === ACTION_TYPE_REVERSED_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await createRelation(user, { fromId: target, toId: element.id, relationship_type: field });
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
  if (contextType === ACTION_TYPE_REVERSED_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await deleteRelationsByFromAndTo(user, target, element.id, field, ABSTRACT_BASIC_RELATIONSHIP);
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
const executeEnrichment = async (user, context, element) => {
  const askConnectors = await internalFindByIds(user, context.values);
  await BluePromise.map(askConnectors, async (connector) => {
    await askElementEnrichmentForConnector(user, element.internal_id, connector.internal_id);
  }, { concurrency: ES_MAX_CONCURRENCY });
};
const executePromote = async (user, element) => {
  // If indicator, promote to observable
  if (element.entity_type === ENTITY_TYPE_INDICATOR) {
    await promoteIndicatorToObservable(user, element.internal_id);
  }
  // If observable, promote to indicator
  if (isStixCyberObservable(element.entity_type)) {
    await promoteObservableToIndicator(user, element.internal_id);
  }
};
const executeRuleApply = async (user, context, element) => {
  const { rule } = context;
  // Execute rules over one element, act as element creation
  const instance = await storeLoadByIdWithRefs(user, element.internal_id);
  const event = await storeCreateEntityEvent(user, instance, '-', { publishStreamEvent: false });
  await rulesApplyHandler([event], [rule]);
};
const executeRuleClean = async (context, element) => {
  const { rule } = context;
  await rulesCleanHandler([element], [rule]);
};
const executeRuleElementRescan = async (user, context, element) => {
  const { rules } = context ?? {};
  const activatedRules = await getActivatedRules();
  // Filter activated rules by context specification
  const rulesToApply = rules ? activatedRules.filter((r) => rules.includes(r.id)) : activatedRules;
  if (rulesToApply.length > 0) {
    const ruleRescanTypes = rulesToApply.map((r) => r.scan.types).flat();
    if (isStixRelationship(element.entity_type)) {
      const needRescan = ruleRescanTypes.includes(element.entity_type);
      if (needRescan) {
        const data = await stixLoadById(user, element.internal_id);
        const event = buildInternalEvent(EVENT_TYPE_CREATE, data);
        await rulesApplyHandler([event]);
      }
    } else if (isStixObject(element.entity_type)) {
      const args = { connectionFormat: false, fromId: element.internal_id };
      const relations = await listAllRelations(user, ABSTRACT_STIX_RELATIONSHIP, args);
      for (let index = 0; index < relations.length; index += 1) {
        const relation = relations[index];
        const needRescan = ruleRescanTypes.includes(relation.entity_type);
        if (needRescan) {
          const data = await stixLoadById(user, relation.internal_id);
          const event = buildInternalEvent(EVENT_TYPE_CREATE, data);
          await rulesApplyHandler([event], rulesToApply);
        }
      }
    }
  }
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
        if (type === ACTION_TYPE_PROMOTE) {
          await executePromote(user, element);
        }
        if (type === ACTION_TYPE_ENRICHMENT) {
          await executeEnrichment(user, context, element);
        }
        if (type === ACTION_TYPE_RULE_APPLY) {
          await executeRuleApply(user, context, element);
        }
        if (type === ACTION_TYPE_RULE_CLEAR) {
          await executeRuleClean(context, element);
        }
        if (type === ACTION_TYPE_RULE_ELEMENT_RESCAN) {
          await executeRuleElementRescan(user, context, element);
        }
      }
    } catch (err) {
      logApp.error('Error executing background task', { error: err, element, actions });
      errors.push({ id: element.id, message: err.message, reason: err.reason });
    }
  }
  return errors;
};

const taskHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([TASK_MANAGER_KEY]);
    const task = await findTaskToExecute();
    // region Task checking
    if (!task) {
      // Nothing to execute.
      return;
    }
    const isQueryTask = task.type === TASK_TYPE_QUERY;
    const isListTask = task.type === TASK_TYPE_LIST;
    const isRuleTask = task.type === TASK_TYPE_RULE;
    if (!isQueryTask && !isListTask && !isRuleTask) {
      logApp.error(`[OPENCTI-MODULE] Task manager can't process ${task.type} type`);
      return;
    }
    // endregion
    const startPatch = { last_execution_date: now() };
    await updateTask(task.id, startPatch);
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
    if (isRuleTask) {
      processingElements = await computeRuleTaskElements(task);
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
      completed: processingElements.length < MAX_TASK_ELEMENTS,
    };
    await updateTask(task.id, patch);
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Task manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Task manager fail to execute', { error: e });
    }
  } finally {
    logApp.debug('[OPENCTI-MODULE] Task manager done');
    if (lock) await lock.unlock();
  }
};
const initTaskManager = () => {
  let scheduler;
  return {
    start: () => {
      logApp.info('[OPENCTI-MODULE] Running task manager');
      scheduler = setIntervalAsync(async () => {
        await taskHandler();
      }, SCHEDULE_TIME);
    },
    shutdown: async () => {
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const taskManager = initTaskManager();

export default taskManager;
