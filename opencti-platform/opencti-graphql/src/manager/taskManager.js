/* eslint-disable camelcase */
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { buildCreateEvent, lockResource } from '../database/redis';
import {
  ACTION_TYPE_ADD,
  ACTION_TYPE_ENRICHMENT,
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
  TASK_TYPE_QUERY,
  TASK_TYPE_RULE,
  updateTask,
} from '../domain/task';
import conf, { logApp } from '../config/conf';
import { resolveUserById } from '../domain/user';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  internalFindByIds,
  internalLoadById, listAllThings,
  mergeEntities,
  patchAttribute,
  stixLoadById,
  storeLoadByIdWithRefs,
} from '../database/middleware';
import { now } from '../utils/format';
import {
  EVENT_TYPE_CREATE,
  INDEX_INTERNAL_OBJECTS,
  isEmptyField,
  READ_DATA_INDICES,
  READ_DATA_INDICES_WITHOUT_INFERRED,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
} from '../database/utils';
import { elPaginate, elUpdate, ES_MAX_CONCURRENCY } from '../database/engine';
import { FunctionalError, TYPE_LOCK_ERROR } from '../config/errors';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP, buildRefRelationKey,
  ENTITY_TYPE_CONTAINER,
  RULE_PREFIX
} from '../schema/general';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { buildInternalEvent, rulesApplyHandler, rulesCleanHandler } from './ruleManager';
import { RULE_MANAGER_USER } from '../rules/rules';
import { buildFilters } from '../database/repository';
import { listAllRelations } from '../database/middleware-loader';
import { getActivatedRules, getRule } from '../domain/rules';
import { isStixRelationship } from '../schema/stixRelationship';
import { isStixObject } from '../schema/stixCoreObject';
import { ENTITY_TYPE_INDICATOR } from '../schema/stixDomainObject';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { promoteObservableToIndicator } from '../domain/stixCyberObservable';
import { promoteIndicatorToObservable } from '../domain/indicator';
import { askElementEnrichmentForConnector } from '../domain/stixCoreObject';
import { creatorFromHistory } from '../domain/log';
import { RELATION_GRANTED_TO, RELATION_OBJECT } from '../schema/stixMetaRelationship';
import { ACTION_TYPE_DELETE, ACTION_TYPE_SHARE, ACTION_TYPE_UNSHARE, TASK_TYPE_LIST } from '../domain/task-common';

// Task manager responsible to execute long manual tasks
// Each API will start is task manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('task_scheduler:interval');
const TASK_MANAGER_KEY = conf.get('task_scheduler:lock_key');

const ACTION_TYPE_ATTRIBUTE = 'ATTRIBUTE';
const ACTION_TYPE_RELATION = 'RELATION';
const ACTION_TYPE_REVERSED_RELATION = 'REVERSED_RELATION';

const findTaskToExecute = async (context) => {
  const tasks = await findAll(context, SYSTEM_USER, {
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
const computeRuleTaskElements = async (context, user, task) => {
  const { task_position, rule, enable } = task;
  const processingElements = [];
  const ruleDefinition = await getRule(context, user, rule);
  if (enable) {
    const { scan } = ruleDefinition;
    const options = {
      first: MAX_TASK_ELEMENTS,
      orderMode: 'asc',
      orderBy: 'updated_at',
      after: task_position,
      ...buildFilters(scan),
    };
    const { edges: elements } = await elPaginate(context, RULE_MANAGER_USER, READ_DATA_INDICES_WITHOUT_INFERRED, options);
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
    const { edges: elements } = await elPaginate(context, RULE_MANAGER_USER, READ_DATA_INDICES, options);
    // Apply the actions for each element
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      const actions = [{ type: ACTION_TYPE_RULE_CLEAR, context: { rule: ruleDefinition } }];
      processingElements.push({ element: element.node, actions, next: element.cursor });
    }
  }
  return processingElements;
};
const computeQueryTaskElements = async (context, user, task) => {
  const { actions, task_position, task_filters, task_search = null, task_excluded_ids = [] } = task;
  const processingElements = [];
  // Fetch the information
  const data = await executeTaskQuery(context, user, task_filters, task_search, task_position);
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
const computeListTaskElements = async (context, user, task) => {
  const { actions, task_position, task_ids } = task;
  const processingElements = [];
  // const expectedNumber = task_ids.length;
  const isUndefinedPosition = R.isNil(task_position) || R.isEmpty(task_position);
  const startIndex = isUndefinedPosition ? 0 : task_ids.findIndex(task_position);
  const ids = R.take(MAX_TASK_ELEMENTS, task_ids.slice(startIndex));
  for (let elementId = 0; elementId < ids.length; elementId += 1) {
    const elementToResolve = task_ids[elementId];
    const element = await internalLoadById(context, user, elementToResolve);
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

const executeDelete = async (context, user, element) => {
  await deleteElementById(context, user, element.internal_id, element.entity_type);
};
const executeAdd = async (context, user, actionContext, element) => {
  const { field, type: contextType, values } = actionContext;
  if (contextType === ACTION_TYPE_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await createRelation(context, user, { fromId: element.id, toId: target, relationship_type: field });
    }
  }
  if (contextType === ACTION_TYPE_REVERSED_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await createRelation(context, user, { fromId: target, toId: element.id, relationship_type: field });
    }
  }
  if (contextType === ACTION_TYPE_ATTRIBUTE) {
    const patch = { [field]: values };
    await patchAttribute(context, user, element.id, element.entity_type, patch, { operation: UPDATE_OPERATION_ADD });
  }
};
const executeRemove = async (context, user, actionContext, element) => {
  const { field, type: contextType, values } = actionContext;
  if (contextType === ACTION_TYPE_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await deleteRelationsByFromAndTo(context, user, element.id, target, field, ABSTRACT_BASIC_RELATIONSHIP);
    }
  }
  if (contextType === ACTION_TYPE_REVERSED_RELATION) {
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await deleteRelationsByFromAndTo(context, user, target, element.id, field, ABSTRACT_BASIC_RELATIONSHIP);
    }
  }
  if (contextType === ACTION_TYPE_ATTRIBUTE) {
    const patch = { [field]: values };
    await patchAttribute(context, user, element.id, element.entity_type, patch, { operation: UPDATE_OPERATION_REMOVE });
  }
};
const executeReplace = async (context, user, actionContext, element) => {
  const { field, type: contextType, values } = actionContext;
  if (contextType === ACTION_TYPE_RELATION) {
    // 01 - Delete all relations of the element
    const rels = await listAllRelations(context, user, field, { fromId: element.id });
    for (let indexRel = 0; indexRel < rels.length; indexRel += 1) {
      const rel = rels[indexRel];
      await deleteElementById(context, user, rel.id, rel.entity_type);
    }
    // 02 - Create new ones
    for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
      const target = values[indexCreate];
      await createRelation(context, user, { fromId: element.id, toId: target, relationship_type: field });
    }
  }
  if (contextType === ACTION_TYPE_ATTRIBUTE) {
    // Special case for creator_id, that will be replaced from history
    if (field === 'creator_id') {
      if (isEmptyField(element.creator_id)) {
        const historicCreator = await creatorFromHistory(context, user, element.internal_id);
        // Direct elastic update to prevent any check/stream propagation
        await elUpdate(element._index, element.id, {
          script: {
            source: 'ctx._source["creator_id"] = params.creator_id;',
            lang: 'painless',
            params: { creator_id: historicCreator }
          },
        });
      }
    } else {
      const patch = { [field]: values };
      await patchAttribute(context, user, element.id, element.entity_type, patch);
    }
  }
};
const executeMerge = async (context, user, actionContext, element) => {
  const { values } = actionContext;
  await mergeEntities(context, user, element.internal_id, values);
};
const executeEnrichment = async (context, user, actionContext, element) => {
  const askConnectors = await internalFindByIds(context, user, actionContext.values);
  await BluePromise.map(askConnectors, async (connector) => {
    await askElementEnrichmentForConnector(context, user, element.internal_id, connector.internal_id);
  }, { concurrency: ES_MAX_CONCURRENCY });
};
const executePromote = async (context, user, element) => {
  // If indicator, promote to observable
  if (element.entity_type === ENTITY_TYPE_INDICATOR) {
    await promoteIndicatorToObservable(context, user, element.internal_id);
  }
  // If observable, promote to indicator
  if (isStixCyberObservable(element.entity_type)) {
    await promoteObservableToIndicator(context, user, element.internal_id);
  }
};
const executeRuleApply = async (context, user, actionContext, element) => {
  const { rule } = actionContext;
  // Execute rules over one element, act as element creation
  const instance = await storeLoadByIdWithRefs(context, user, element.internal_id);
  if (!instance) {
    throw FunctionalError('Cant find element to scan', { id: element.internal_id });
  }
  const event = buildCreateEvent(user, instance, '-', {});
  await rulesApplyHandler(context, user, [event], [rule]);
};
const executeRuleClean = async (context, user, actionContext, element) => {
  const { rule } = actionContext;
  await rulesCleanHandler(context, user, [element], [rule]);
};
const executeRuleElementRescan = async (context, user, actionContext, element) => {
  const { rules } = actionContext ?? {};
  const activatedRules = await getActivatedRules(context);
  // Filter activated rules by context specification
  const rulesToApply = rules ? activatedRules.filter((r) => rules.includes(r.id)) : activatedRules;
  if (rulesToApply.length > 0) {
    const ruleRescanTypes = rulesToApply.map((r) => r.scan.types).flat();
    if (isStixRelationship(element.entity_type)) {
      const needRescan = ruleRescanTypes.includes(element.entity_type);
      if (needRescan) {
        const data = await stixLoadById(context, user, element.internal_id);
        const event = buildInternalEvent(EVENT_TYPE_CREATE, data);
        await rulesApplyHandler(context, user, [event]);
      }
    } else if (isStixObject(element.entity_type)) {
      const args = { connectionFormat: false, fromId: element.internal_id };
      const relations = await listAllRelations(context, user, ABSTRACT_STIX_RELATIONSHIP, args);
      for (let index = 0; index < relations.length; index += 1) {
        const relation = relations[index];
        const needRescan = ruleRescanTypes.includes(relation.entity_type);
        if (needRescan) {
          const data = await stixLoadById(context, user, relation.internal_id);
          const event = buildInternalEvent(EVENT_TYPE_CREATE, data);
          await rulesApplyHandler(context, user, [event], rulesToApply);
        }
      }
    }
  }
};
const executeShare = async (context, user, actionContext, element) => {
  const { values } = actionContext;
  for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
    const target = values[indexCreate];
    await createRelation(context, user, { fromId: element.id, toId: target, relationship_type: RELATION_GRANTED_TO });
  }
};
const executeUnshare = async (context, user, actionContext, element) => {
  const { values } = actionContext;
  for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
    const target = values[indexCreate];
    // resolve all containers of this element
    const args = { filters: [{ key: buildRefRelationKey(RELATION_OBJECT), values: [element.id] }], };
    const containers = await listAllThings(context, user, [ENTITY_TYPE_CONTAINER], args);
    const grantedTo = containers.map((n) => n[buildRefRelationKey(RELATION_GRANTED_TO)]).flat();
    if (!grantedTo.includes(target)) {
      await deleteRelationsByFromAndTo(context, user, element.id, target, RELATION_GRANTED_TO, ABSTRACT_BASIC_RELATIONSHIP);
    }
  }
};
const executeProcessing = async (context, user, processingElements) => {
  const errors = [];
  for (let index = 0; index < processingElements.length; index += 1) {
    const { element, actions } = processingElements[index];
    try {
      for (let actionIndex = 0; actionIndex < actions.length; actionIndex += 1) {
        const { type, context: actionContext } = actions[actionIndex];
        if (type === ACTION_TYPE_DELETE) {
          await executeDelete(context, user, element);
          break; // You cant have multiple actions on deletion, just stopping the loop.
        }
        if (type === ACTION_TYPE_ADD) {
          await executeAdd(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_REMOVE) {
          await executeRemove(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_REPLACE) {
          await executeReplace(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_MERGE) {
          await executeMerge(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_PROMOTE) {
          await executePromote(context, user, element);
        }
        if (type === ACTION_TYPE_ENRICHMENT) {
          await executeEnrichment(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_RULE_APPLY) {
          await executeRuleApply(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_RULE_CLEAR) {
          await executeRuleClean(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_RULE_ELEMENT_RESCAN) {
          await executeRuleElementRescan(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_SHARE) {
          await executeShare(context, user, actionContext, element);
        }
        if (type === ACTION_TYPE_UNSHARE) {
          await executeUnshare(context, user, actionContext, element);
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
    const context = executionContext('task_manager');
    const task = await findTaskToExecute(context);
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
    await updateTask(context, task.id, startPatch);
    // Fetch the user responsible for the task
    const rawUser = await resolveUserById(context, task.initiator_id);
    const user = { ...rawUser, origin: { user_id: rawUser.id, referer: 'background_task' } };
    let processingElements;
    if (isQueryTask) {
      processingElements = await computeQueryTaskElements(context, user, task);
    }
    if (isListTask) {
      processingElements = await computeListTaskElements(context, user, task);
    }
    if (isRuleTask) {
      processingElements = await computeRuleTaskElements(context, user, task);
    }
    // Process the elements (empty = end of execution)
    if (processingElements.length > 0) {
      const errors = await executeProcessing(context, user, processingElements);
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
    await updateTask(context, task.id, patch);
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
