/* eslint-disable camelcase */
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
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
  DEFAULT_ALLOWED_TASK_ENTITY_TYPES,
  executeTaskQuery,
  findAll,
  MAX_TASK_ELEMENTS,
  updateTask
} from '../domain/backgroundTask';
import conf, { booleanConf, logApp } from '../config/conf';
import { resolveUserByIdFromCache } from '../domain/user';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  listAllThings,
  mergeEntities,
  patchAttribute,
  stixLoadById,
  storeLoadByIdWithRefs
} from '../database/middleware';
import { now } from '../utils/format';
import { EVENT_TYPE_CREATE, READ_DATA_INDICES, READ_DATA_INDICES_WITHOUT_INFERRED, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { elPaginate, elUpdate, ES_MAX_CONCURRENCY } from '../database/engine';
import { ForbiddenAccess, FunctionalError, TYPE_LOCK_ERROR, UnsupportedError, ValidationError } from '../config/errors';
import {
  ABSTRACT_BASIC_RELATIONSHIP,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_RELATIONSHIP,
  buildRefRelationKey,
  ENTITY_TYPE_CONTAINER,
  INPUT_OBJECTS,
  RULE_PREFIX
} from '../schema/general';
import { executionContext, getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, RULE_MANAGER_USER, SYSTEM_USER } from '../utils/access';
import { buildInternalEvent, rulesApplyHandler, rulesCleanHandler } from './ruleManager';
import { buildEntityFilters, internalFindByIds, listAllRelations } from '../database/middleware-loader';
import { getActivatedRules, getRule } from '../domain/rules';
import { isStixRelationship } from '../schema/stixRelationship';
import { isStixObject } from '../schema/stixCoreObject';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { promoteObservableToIndicator } from '../domain/stixCyberObservable';
import { indicatorEditField, promoteIndicatorToObservables } from '../modules/indicator/indicator-domain';
import { askElementEnrichmentForConnector } from '../domain/stixCoreObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT } from '../schema/stixRefRelationship';
import {
  ACTION_TYPE_COMPLETE_DELETE,
  ACTION_TYPE_DELETE,
  ACTION_TYPE_RESTORE,
  ACTION_TYPE_SHARE,
  ACTION_TYPE_SHARE_MULTIPLE,
  ACTION_TYPE_UNSHARE,
  ACTION_TYPE_UNSHARE_MULTIPLE,
  TASK_TYPE_LIST,
  TASK_TYPE_QUERY,
  TASK_TYPE_RULE
} from '../domain/backgroundTask-common';
import { validateUpdatableAttribute } from '../schema/schema-validator';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { processDeleteOperation, restoreDelete } from '../modules/deleteOperation/deleteOperation-domain';
import { addOrganizationRestriction, removeOrganizationRestriction } from '../domain/stix';
import { stixDomainObjectAddRelation } from '../domain/stixDomainObject';
import { BackgroundTaskScope } from '../generated/graphql';
import { ENTITY_TYPE_INTERNAL_FILE } from '../schema/internalObject';
import { deleteFile } from '../database/file-storage';
import { checkUserIsAdminOnDashboard } from '../modules/publicDashboard/publicDashboard-utils';

// Task manager responsible to execute long manual tasks
// Each API will start is task manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('task_scheduler:interval');
const TASK_MANAGER_KEY = conf.get('task_scheduler:lock_key');

const ACTION_ON_CONTAINER_FIELD = 'container-object';
const ACTION_TYPE_ATTRIBUTE = 'ATTRIBUTE';
const ACTION_TYPE_RELATION = 'RELATION';
const ACTION_TYPE_REVERSED_RELATION = 'REVERSED_RELATION';

const MAX_TASK_ERRORS = 100;

let running = false;

const findTaskToExecute = async (context) => {
  const tasks = await findAll(context, SYSTEM_USER, {
    connectionFormat: false,
    orderBy: 'created_at',
    orderMode: 'asc',
    limit: 1,
    filters: {
      mode: 'and',
      filters: [{ key: 'completed', values: [false] }],
      filterGroups: [],
    },
    noFiltersChecking: true
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
    const actions = [{ type: ACTION_TYPE_RULE_APPLY, context: { rule: ruleDefinition } }];
    const options = {
      first: MAX_TASK_ELEMENTS,
      orderMode: 'asc',
      orderBy: 'updated_at',
      after: task_position,
      ...buildEntityFilters(scan.types, scan),
    };
    const { edges: elements } = await elPaginate(context, RULE_MANAGER_USER, READ_DATA_INDICES_WITHOUT_INFERRED, options);
    // Apply the actions for each element
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      processingElements.push({ element: element.node, next: element.cursor });
    }
    return { actions, elements: processingElements };
  }
  const filters = {
    mode: 'and',
    filters: [{ key: `${RULE_PREFIX}${rule}`, values: ['EXISTS'] }],
    filterGroups: [],
  };
  const actions = [{ type: ACTION_TYPE_RULE_CLEAR, context: { rule: ruleDefinition } }];
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
    processingElements.push({ element: element.node, next: element.cursor });
  }
  return { actions, elements: processingElements };
};

export const computeQueryTaskElements = async (context, user, task) => {
  const { actions, task_position, task_filters, task_search = null, task_excluded_ids = [], scope } = task;
  const processingElements = [];
  // Fetch the information
  // note that the query is filtered to allow only elements with matching confidence level
  const data = await executeTaskQuery(context, user, task_filters, task_search, scope, task_position);
  // const expectedNumber = data.pageInfo.globalCount;
  const elements = data.edges;
  // Apply the actions for each element
  for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
    const element = elements[elementIndex];
    if (!task_excluded_ids.includes(element.node.id)) { // keep only the elements that are not excluded (via unticked checkboxes in UI)
      processingElements.push({ element: element.node, next: element.cursor });
    }
  }
  return { actions, elements: processingElements };
};
const computeListTaskElements = async (context, user, task) => {
  const { actions, task_position, task_ids, scope } = task;
  const isUndefinedPosition = R.isNil(task_position) || R.isEmpty(task_position);
  const startIndex = isUndefinedPosition ? 0 : task_ids.findIndex((id) => task_position === id) + 1;
  const ids = R.take(MAX_TASK_ELEMENTS, task_ids.slice(startIndex));

  // processing elements in descending order makes possible restoring from trash elements with dependencies
  let type = DEFAULT_ALLOWED_TASK_ENTITY_TYPES;
  if (scope === BackgroundTaskScope.Import) {
    type = [ENTITY_TYPE_INTERNAL_FILE];
  } else if (scope === BackgroundTaskScope.PublicDashboard) {
    type = [ENTITY_TYPE_PUBLIC_DASHBOARD];
  } else if (scope === BackgroundTaskScope.Dashboard || scope === BackgroundTaskScope.Investigation) {
    type = [ENTITY_TYPE_WORKSPACE];
  }
  const options = {
    type,
    orderMode: 'desc',
    orderBy: scope === BackgroundTaskScope.Import ? 'lastModified' : 'created_at',
  };
  const elements = await internalFindByIds(context, user, ids, options);
  const processingElements = elements.map((element) => ({ element, next: element.id }));
  return { actions, elements: processingElements };
};
const appendTaskErrors = async (task, errors) => {
  if (errors.length === 0) {
    return;
  }
  const params = { errors: errors.map((err) => ({
    timestamp: now(),
    id: err.id,
    message: err.message,
  })) };
  const source = `if (ctx._source.errors.length < ${MAX_TASK_ERRORS}) { ctx._source.errors.addAll(params.errors); }`;
  await elUpdate(task._index, task.id, { script: { source, lang: 'painless', params } });
};

const generatePatch = (field, values, type) => {
  const basicErrors = validateUpdatableAttribute(type, { [field]: values });
  const extensionErrors = validateUpdatableAttribute(type, { [`x_opencti_${field}`]: values });
  if (basicErrors.length === 0) {
    return { [field]: values };
  }
  if (extensionErrors.length === 0) {
    return { [`x_opencti_${field}`]: values };
  }
  throw ValidationError('You cannot update incompatible attribute', basicErrors.at(0) ?? extensionErrors.at(0));
};

const executeDelete = async (context, user, element, scope) => {
  // Check the user has sufficient level of access to delete the element.
  const userAccess = getUserAccessRight(user, element);
  if (userAccess !== MEMBER_ACCESS_RIGHT_ADMIN) {
    throw ForbiddenAccess();
  }
  // Specific case for public dashboards because need to check authorized
  // members of the associated custom dashboard instead.
  if (scope === BackgroundTaskScope.PublicDashboard) {
    await checkUserIsAdminOnDashboard(context, user, element.id);
  }
  if (scope === BackgroundTaskScope.Import) {
    await deleteFile(context, user, element.id);
  } else {
    await deleteElementById(context, user, element.internal_id, element.entity_type);
  }
};

const executeCompleteDelete = async (context, user, element) => {
  await processDeleteOperation(context, user, element.internal_id, { isRestoring: false });
};
const executeRestore = async (context, user, element) => {
  await restoreDelete(context, user, element.internal_id);
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
    const patch = generatePatch(field, values, element.entity_type);
    const operations = { [field]: UPDATE_OPERATION_ADD };
    await patchAttribute(context, user, element.id, element.entity_type, patch, { operations });
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
    const patch = generatePatch(field, values, element.entity_type);
    const operations = { [field]: UPDATE_OPERATION_REMOVE };
    await patchAttribute(context, user, element.id, element.entity_type, patch, { operations });
  }
};

const executeReplaceScoreForIndicator = async (context, user, id, field, values) => {
  const input = {
    key: field,
    value: values
  };
  await indicatorEditField(context, user, id, [input]);
};

export const executeReplace = async (context, user, actionContext, element) => {
  const { field, type: contextType, values } = actionContext;
  // About indicators, when score is changing, it should change some other values
  if (element.entity_type === ENTITY_TYPE_INDICATOR && field === 'x_opencti_score') {
    await executeReplaceScoreForIndicator(context, user, element.id, field, values);
  }
  let input = field;
  if (contextType === ACTION_TYPE_RELATION) {
    input = schemaRelationsRefDefinition.convertDatabaseNameToInputName(element.entity_type, field);
  }
  const patch = generatePatch(input, values, element.entity_type);
  await patchAttribute(context, user, element.id, element.entity_type, patch);
};
const executeMerge = async (context, user, actionContext, element) => {
  const { values } = actionContext;
  await mergeEntities(context, user, element.internal_id, values);
};
const executeEnrichment = async (context, user, actionContext, element) => {
  const askConnectors = await internalFindByIds(context, user, actionContext.values);
  await BluePromise.map(askConnectors, async (connector) => {
    await askElementEnrichmentForConnector(context, user, element.standard_id, connector.internal_id);
  }, { concurrency: ES_MAX_CONCURRENCY });
};

export const executePromoteIndicatorToObservables = async (context, user, element, containerId) => {
  const createdObservables = await promoteIndicatorToObservables(context, user, element.internal_id);
  if (containerId && createdObservables.length > 0) {
    await Promise.all(
      createdObservables.map((observable) => {
        const relationInput = {
          toId: observable.id,
          relationship_type: 'object'
        };
        return stixDomainObjectAddRelation(context, user, containerId, relationInput);
      })
    );
  }
};

export const executePromoteObservableToIndicator = async (context, user, element, containerId) => {
  const createdIndicator = await promoteObservableToIndicator(context, user, element.internal_id);
  if (containerId && createdIndicator) {
    const relationInput = {
      toId: createdIndicator.id,
      relationship_type: 'object'
    };
    await stixDomainObjectAddRelation(context, user, containerId, relationInput);
  }
};

export const executePromote = async (context, user, element, containerId) => {
  // If indicator, promote to observable
  if (element.entity_type === ENTITY_TYPE_INDICATOR) {
    await executePromoteIndicatorToObservables(context, user, element, containerId);
  }
  // If observable, promote to indicator
  if (isStixCyberObservable(element.entity_type)) {
    await executePromoteObservableToIndicator(context, user, element, containerId);
  }
};
const executeRuleApply = async (context, user, actionContext, element) => {
  const { rule } = actionContext;
  // Execute rules over one element, act as element creation
  const instance = await storeLoadByIdWithRefs(context, user, element.internal_id);
  if (!instance) {
    throw FunctionalError('Cant find element to scan', { id: element.internal_id });
  }
  const event = buildCreateEvent(user, instance, '-');
  await rulesApplyHandler(context, user, [event], [rule]);
};
const executeRuleClean = async (context, user, actionContext, element) => {
  const { rule } = actionContext;
  await rulesCleanHandler(context, user, [element], [rule]);
};
const executeRuleElementRescan = async (context, user, actionContext, element) => {
  const { rules } = actionContext ?? {};
  const activatedRules = await getActivatedRules(context, SYSTEM_USER);
  // Filter activated rules by context specification
  const rulesToApply = rules ? activatedRules.filter((r) => rules.includes(r.id)) : activatedRules;
  if (rulesToApply.length > 0) {
    const ruleRescanTypes = rulesToApply.map((r) => r.scan.types).flat();
    if (isStixRelationship(element.entity_type)) {
      const needRescan = ruleRescanTypes.includes(element.entity_type);
      if (needRescan) {
        const data = await stixLoadById(context, user, element.internal_id);
        const event = buildInternalEvent(EVENT_TYPE_CREATE, data);
        await rulesApplyHandler(context, user, [event], rulesToApply);
      }
    } else if (isStixObject(element.entity_type)) {
      const listCallback = async (relations) => {
        for (let index = 0; index < relations.length; index += 1) {
          const relation = relations[index];
          const needRescan = ruleRescanTypes.includes(relation.entity_type);
          if (needRescan) {
            const data = await stixLoadById(context, user, relation.internal_id);
            const event = buildInternalEvent(EVENT_TYPE_CREATE, data);
            await rulesApplyHandler(context, user, [event], rulesToApply);
          }
        }
      };
      const args = { connectionFormat: false, fromId: element.internal_id, callback: listCallback };
      await listAllRelations(context, user, ABSTRACT_STIX_RELATIONSHIP, args);
    }
  }
};
const executeShare = async (context, user, actionContext, element) => {
  const { values } = actionContext;
  for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
    const target = values[indexCreate];
    const currentGrants = element[buildRefRelationKey(RELATION_GRANTED_TO)] ?? [];
    if (!currentGrants.includes(target)) {
      await createRelation(context, user, { fromId: element.id, toId: target, relationship_type: RELATION_GRANTED_TO });
    }
  }
};
const executeUnshare = async (context, user, actionContext, element) => {
  const { values } = actionContext;
  for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
    const target = values[indexCreate];
    // resolve all containers of this element
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: buildRefRelationKey(RELATION_OBJECT), values: [element.id] }],
        filterGroups: []
      },
      noFiltersChecking: true
    };
    const containers = await listAllThings(context, user, [ENTITY_TYPE_CONTAINER], args);
    const grantedTo = containers.map((n) => n[buildRefRelationKey(RELATION_GRANTED_TO)]).flat();
    if (!grantedTo.includes(target)) {
      await deleteRelationsByFromAndTo(context, user, element.id, target, RELATION_GRANTED_TO, ABSTRACT_BASIC_RELATIONSHIP);
    }
  }
};
const executeShareMultiple = async (context, user, actionContext, element) => {
  await Promise.all(actionContext.values.map((organizationId) => addOrganizationRestriction(context, user, element.id, organizationId)));
};
const executeUnshareMultiple = async (context, user, actionContext, element) => {
  await Promise.all(actionContext.values.map((organizationId) => removeOrganizationRestriction(context, user, element.id, organizationId)));
};
const executeProcessing = async (context, user, job, scope) => {
  const errors = [];
  for (let index = 0; index < job.actions.length; index += 1) {
    const { type, context: actionContext, containerId } = job.actions[index];
    const { field, values, options } = actionContext ?? {};
    // Containers specific operations
    // Can be done in one shot patch modification.
    if (field === ACTION_ON_CONTAINER_FIELD) {
      for (let valueIndex = 0; valueIndex < values.length; valueIndex += 1) {
        const value = values[valueIndex];
        try {
          const objects = job.elements.map((e) => e.element.internal_id).filter((id) => value !== id);
          let finalObjects = objects;
          if (options?.includeNeighbours) {
            // For relationships, include fromId and toId
            finalObjects = R.uniq([
              ...finalObjects,
              ...job.elements
                .filter((e) => e.element.fromId && e.element.toId)
                .filter((e) => value !== e.element.internal_id)
                .map((e) => [e.element.fromId, e.element.toId])
                .flat()
            ]);
            // For all objects, resolve stix core
            for (let objectIndex = 0; objectIndex < objects.length; objectIndex += 1) {
              const relations = await listAllRelations(context, user, ABSTRACT_STIX_CORE_RELATIONSHIP, {
                fromOrToId: objects[objectIndex],
                baseData: true
              });
              finalObjects = R.uniq(
                [
                  ...finalObjects,
                  ...relations.map((r) => r.id),
                  ...relations.map((r) => (objects[objectIndex] === r.fromId ? r.toId : r.fromId))
                ]
              );
            }
          }
          const patch = { [INPUT_OBJECTS]: finalObjects };
          const operations = { [INPUT_OBJECTS]: type.toLowerCase() }; // add, remove, replace
          await patchAttribute(context, user, value, ENTITY_TYPE_CONTAINER, patch, { operations });
        } catch (err) {
          logApp.error(err);
          if (errors.length < MAX_TASK_ERRORS) {
            errors.push({ id: value, message: err.message, reason: err.reason });
          }
        }
      }
    } else { // Classic action, need to be apply on each element
      for (let elementIndex = 0; elementIndex < job.elements.length; elementIndex += 1) {
        const { element } = job.elements[elementIndex];
        try {
          if (type === ACTION_TYPE_DELETE) {
            await executeDelete(context, user, element, scope);
          }
          if (type === ACTION_TYPE_COMPLETE_DELETE) {
            await executeCompleteDelete(context, user, element);
          }
          if (type === ACTION_TYPE_RESTORE) {
            await executeRestore(context, user, element);
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
            await executePromote(context, user, element, containerId);
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
          if (type === ACTION_TYPE_SHARE_MULTIPLE) {
            await executeShareMultiple(context, user, actionContext, element);
          }
          if (type === ACTION_TYPE_UNSHARE_MULTIPLE) {
            await executeUnshareMultiple(context, user, actionContext, element);
          }
        } catch (err) {
          logApp.error(err);
          if (errors.length < MAX_TASK_ERRORS) {
            errors.push({ id: element.id, message: `${err.message}${err.data?.reason ? ` - ${err.reason}` : ''}` });
          }
        }
      }
    }
  }
  return errors;
};

const taskHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([TASK_MANAGER_KEY], { retryCount: 0 });
    running = true;
    const context = executionContext('task_manager', SYSTEM_USER);
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
      logApp.error(UnsupportedError('Unsupported task type', { type: task.type }));
      return;
    }
    // endregion
    const startPatch = { last_execution_date: now() };
    await updateTask(context, task.id, startPatch);
    // Fetch the user responsible for the task
    const rawUser = await resolveUserByIdFromCache(context, task.initiator_id);
    const user = { ...rawUser, origin: { user_id: rawUser.id, referer: 'background_task' } };
    let jobToExecute;
    if (isQueryTask) {
      jobToExecute = await computeQueryTaskElements(context, user, task);
    }
    if (isListTask) {
      jobToExecute = await computeListTaskElements(context, user, task);
    }
    if (isRuleTask) {
      jobToExecute = await computeRuleTaskElements(context, user, task);
    }
    // Process the elements (empty = end of execution)
    const processingElements = jobToExecute.elements;
    if (processingElements.length > 0) {
      lock.signal.throwIfAborted();
      const errors = await executeProcessing(context, user, jobToExecute, task.scope);
      await appendTaskErrors(task, errors);
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
      logApp.error(e, { manager: 'TASK_MANAGER' });
    }
  } finally {
    running = false;
    logApp.debug('[OPENCTI-MODULE] Task manager done');
    if (lock) await lock.unlock();
  }
};
const initTaskManager = () => {
  let scheduler;
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Running task manager');
      scheduler = setIntervalAsync(async () => {
        await taskHandler();
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'TASK_MANAGER',
        enable: booleanConf('task_scheduler:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping task manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const taskManager = initTaskManager();

export default taskManager;
