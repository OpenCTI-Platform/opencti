/* eslint-disable camelcase */
import { v4 as uuidv4 } from 'uuid';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { lockResources } from '../lock/master-lock';
import { buildQueryFilters, findBackgroundTask, updateTask } from '../domain/backgroundTask';
import conf, { booleanConf, logApp } from '../config/conf';
import { resolveUserByIdFromCache } from '../domain/user';
import { storeLoadByIdsWithRefs } from '../database/middleware';
import { now } from '../utils/format';
import { isEmptyField, READ_DATA_INDICES, READ_DATA_INDICES_WITHOUT_INFERRED } from '../database/utils';
import { elList } from '../database/engine';
import { FunctionalError, TYPE_LOCK_ERROR } from '../config/errors';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, INPUT_OBJECTS, RULE_PREFIX } from '../schema/general';
import { executionContext, isUserInPlatformOrganization, RULE_MANAGER_USER, SYSTEM_USER } from '../utils/access';
import { buildEntityFilters, internalFindByIds, internalLoadById, fullRelationsList } from '../database/middleware-loader';
import { getRule } from '../domain/rules';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { generateIndicatorFromObservable } from '../domain/stixCyberObservable';
import {
  ACTION_TYPE_ADD,
  ACTION_TYPE_ADD_GROUPS,
  ACTION_TYPE_ADD_ORGANIZATIONS,
  ACTION_TYPE_COMPLETE_DELETE,
  ACTION_TYPE_DELETE,
  ACTION_TYPE_ENRICHMENT,
  ACTION_TYPE_MERGE,
  ACTION_TYPE_PROMOTE,
  ACTION_TYPE_REMOVE,
  ACTION_TYPE_REMOVE_AUTH_MEMBERS,
  ACTION_TYPE_REMOVE_FROM_DRAFT,
  ACTION_TYPE_REMOVE_GROUPS,
  ACTION_TYPE_REMOVE_ORGANIZATIONS,
  ACTION_TYPE_REPLACE,
  ACTION_TYPE_RESTORE,
  ACTION_TYPE_RULE_APPLY,
  ACTION_TYPE_RULE_CLEAR,
  ACTION_TYPE_RULE_ELEMENT_RESCAN,
  ACTION_TYPE_SEND_EMAIL,
  ACTION_TYPE_SHARE,
  ACTION_TYPE_SHARE_MULTIPLE,
  ACTION_TYPE_UNSHARE,
  ACTION_TYPE_UNSHARE_MULTIPLE,
  createWorkForBackgroundTask,
  TASK_TYPE_LIST,
  TASK_TYPE_QUERY,
  TASK_TYPE_RULE
} from '../domain/backgroundTask-common';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { getDraftContext } from '../utils/draftContext';
import { getBestBackgroundConnectorId, pushToWorkerForConnector } from '../database/rabbitmq';
import { updateExpectationsNumber, updateProcessedTime } from '../domain/work';
import { convertStoreToStix_2_1, convertTypeToStixType } from '../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { extractValidObservablesFromIndicatorPattern } from '../utils/syntax';
import { generateStandardId } from '../schema/identifier';
import { isBasicRelationship } from '../schema/stixRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { getEntityFromCache } from '../database/cache';
import { objects as getContainerObjects } from '../domain/container';
import { doYield } from '../utils/eventloop-utils';

// Task manager responsible to execute long manual tasks
// Each API will start is task manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('task_scheduler:interval');
const TASK_MANAGER_KEY = conf.get('task_scheduler:lock_key');
const TASK_CONCURRENCY = parseInt(conf.get('task_scheduler:max_concurrency') ?? '4', 10);

let running = false;

const findTasksToExecute = async (context) => {
  return findBackgroundTask(context, SYSTEM_USER, {
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
};

export const taskRule = async (context, user, task, callback) => {
  const { task_position, rule, enable } = task;
  const ruleDefinition = await getRule(context, user, rule);
  if (enable) {
    const { scan } = ruleDefinition;
    // task_position is no longer used, but we still handle it to properly process task that were processing before task migrated to worker
    const options = { baseData: true, orderMode: 'asc', orderBy: 'updated_at', ...buildEntityFilters(scan.types, scan), after: task_position };
    const finalOpts = { ...options, callback };
    await elList(context, RULE_MANAGER_USER, READ_DATA_INDICES_WITHOUT_INFERRED, finalOpts);
  } else {
    const filters = {
      mode: 'and',
      filters: [{ key: `${RULE_PREFIX}${rule}`, values: ['EXISTS'] }],
      filterGroups: [],
    };
    // task_position is no longer used, but we still handle it to properly process task that were processing before task migrated to worker
    const options = { baseData: true, orderMode: 'asc', orderBy: 'updated_at', filters, after: task_position };
    const finalOpts = { ...options, callback };
    await elList(context, RULE_MANAGER_USER, READ_DATA_INDICES, finalOpts);
  }
};

export const taskQuery = async (context, user, task, callback) => {
  const { task_position, task_filters, task_search = null, task_excluded_ids = [], scope, task_order_mode } = task;
  const options = await buildQueryFilters(context, user, task_filters, task_search, task_position, scope, task_order_mode, task_excluded_ids);
  const finalOpts = { ...options, baseData: true, callback };
  await elList(context, user, READ_DATA_INDICES, finalOpts);
};

export const taskList = async (context, user, task, callback) => {
  const { task_position, task_ids } = task;
  // task_position is no longer used, but we still handle it to properly process task that were processing before task migrated to worker
  const isUndefinedPosition = R.isNil(task_position) || R.isEmpty(task_position);
  const startIndex = isUndefinedPosition ? 0 : task_ids.findIndex((id) => task_position === id) + 1;
  const ids = task_ids.slice(startIndex);
  const options = {
    baseData: true,
    includeDeletedInDraft: true,
  };
  const elements = await internalFindByIds(context, user, ids, options);
  callback(elements);
};

const throwErrorInDraftContext = (context, user, actionType) => {
  if (!getDraftContext(context, user)) {
    return;
  }
  if (actionType === ACTION_TYPE_COMPLETE_DELETE
      || actionType === ACTION_TYPE_RESTORE
      || actionType === ACTION_TYPE_RULE_APPLY
      || actionType === ACTION_TYPE_RULE_CLEAR
      || actionType === ACTION_TYPE_RULE_ELEMENT_RESCAN
      || actionType === ACTION_TYPE_SHARE
      || actionType === ACTION_TYPE_UNSHARE
      || actionType === ACTION_TYPE_SHARE_MULTIPLE
      || actionType === ACTION_TYPE_UNSHARE_MULTIPLE
      || actionType === ACTION_TYPE_SEND_EMAIL) {
    throw FunctionalError('Cannot execute this task type in draft', { actionType });
  }
};

const isShareAction = (actionType) => {
  return actionType === ACTION_TYPE_SHARE || actionType === ACTION_TYPE_SHARE_MULTIPLE;
};

const isUnshareAction = (actionType) => {
  return actionType === ACTION_TYPE_UNSHARE || actionType === ACTION_TYPE_UNSHARE_MULTIPLE;
};

const baseOperationBuilder = (actionType, operations, element) => {
  const baseOperationObject = {};
  // Knowledge management
  if (actionType === 'KNOWLEDGE_CHANGE') {
    baseOperationObject.opencti_operation = 'patch';
    baseOperationObject.opencti_field_patch = operations.map((action) => {
      let attrKey = action.context.field;
      if (action.context.type === 'RELATION') {
        attrKey = schemaRelationsRefDefinition
          .convertDatabaseNameToInputName(element.entity_type, action.context.field);
      }
      return { key: attrKey, value: action.context.values, operation: action.type.toLowerCase() };
    });
  }
  if (actionType === 'KNOWLEDGE_TRASH') {
    baseOperationObject.opencti_operation = 'delete';
  }
  if (actionType === ACTION_TYPE_RESTORE) {
    baseOperationObject.opencti_operation = 'restore';
  }
  if (actionType === 'KNOWLEDGE_REMOVE') {
    baseOperationObject.opencti_operation = 'delete_force';
  }
  if (actionType === ACTION_TYPE_ENRICHMENT) {
    baseOperationObject.opencti_operation = 'enrichment';
    baseOperationObject.connector_ids = operations[0].context.values;
  }
  if (actionType === ACTION_TYPE_MERGE) {
    baseOperationObject.opencti_operation = 'merge';
    baseOperationObject.merge_target_id = element.id; // To be compliant with current worker implementation
    baseOperationObject.merge_source_ids = operations[0].context.values;
  }
  // Draft management
  if (actionType === ACTION_TYPE_REMOVE_FROM_DRAFT) {
    baseOperationObject.opencti_operation = 'revert_draft';
  }
  // Rule management
  if (actionType === ACTION_TYPE_RULE_APPLY) {
    baseOperationObject.opencti_operation = actionType.toLowerCase();
    baseOperationObject.opencti_rule = operations[0].context.rule_id;
  }
  if (actionType === ACTION_TYPE_RULE_CLEAR) {
    baseOperationObject.opencti_operation = actionType.toLowerCase();
    baseOperationObject.opencti_rule = operations[0].context.rule_id;
  }
  if (actionType === ACTION_TYPE_RULE_ELEMENT_RESCAN) {
    baseOperationObject.opencti_operation = 'rules_rescan';
  }
  // Share / Unshare
  if (isShareAction(actionType)) {
    baseOperationObject.opencti_operation = 'share';
    baseOperationObject.sharing_organization_ids = operations[0].context.values;
    baseOperationObject.sharing_direct_container = false;
  }
  if (isUnshareAction(actionType)) {
    baseOperationObject.opencti_operation = 'unshare';
    baseOperationObject.sharing_organization_ids = operations[0].context.values;
    baseOperationObject.sharing_direct_container = false;
  }
  // Access management
  if (actionType === ACTION_TYPE_REMOVE_AUTH_MEMBERS) {
    baseOperationObject.opencti_operation = 'clear_access_restriction';
  }
  // User orga management
  if (actionType === ACTION_TYPE_ADD_ORGANIZATIONS) {
    baseOperationObject.opencti_operation = 'add_organizations';
    baseOperationObject.organization_ids = operations[0].context.values;
  }
  if (actionType === ACTION_TYPE_REMOVE_ORGANIZATIONS) {
    baseOperationObject.opencti_operation = 'remove_organizations';
    baseOperationObject.organization_ids = operations[0].context.values;
  }
  // User group management
  if (actionType === ACTION_TYPE_ADD_GROUPS) {
    baseOperationObject.opencti_operation = 'add_groups';
    baseOperationObject.group_ids = operations[0].context.values;
  }
  if (actionType === ACTION_TYPE_REMOVE_GROUPS) {
    baseOperationObject.opencti_operation = 'remove_groups';
    baseOperationObject.group_ids = operations[0].context.values;
  }
  if (actionType === ACTION_TYPE_SEND_EMAIL) {
    baseOperationObject.opencti_operation = 'send_email';
    baseOperationObject.template_id = operations[0].context.values;
  }
  return baseOperationObject;
};

const sendResultToQueue = async (context, user, task, objects, opts = {}) => {
  // Send actions to queue
  const stixBundle = JSON.stringify({ id: uuidv4(), type: 'bundle', objects });
  const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
  // Only add explicit expectation if the worker will not split anything
  if (objects.length === 1 || opts.forceNoSplit) {
    await updateExpectationsNumber(context, user, task.work_id, objects.length);
  }
  await pushToWorkerForConnector(task.connector_id, {
    type: 'bundle',
    applicant_id: user.id,
    content,
    work_id: task.work_id,
    draft_id: task.draft_context ?? null,
    no_split: opts.forceNoSplit ?? false
  });
};

const buildBundleElement = (element, actionType, operations) => {
  const baseObject = {
    id: element.standard_id,
    type: convertTypeToStixType(element.entity_type),
    extensions: {
      [STIX_EXT_OCTI]: {
        id: element.internal_id,
        type: element.entity_type,
        ...baseOperationBuilder(actionType, operations, element),
      }
    }
  };
  // region Handle specific relationship attributes
  if (isStixSightingRelationship(element.entity_type)) {
    baseObject.sighting_of_ref = element.fromId;
    baseObject.where_sighted_refs = [element.toId];
  } else if (isBasicRelationship(element.entity_type)) {
    baseObject.source_ref = element.fromId;
    baseObject.target_ref = element.toId;
  }
  return baseObject;
};

const standardOperationCallback = async (context, user, task, actionType, operations) => {
  let totalProcessed = task.task_processed_number;
  return async (elements) => {
    // Build limited stix object to limit memory footprint
    const objects = [];
    for (let index = 0; index < elements.length; index += 1) {
      await doYield();
      const e = elements[index];
      const object = buildBundleElement(e, actionType, operations);
      objects.push(object);
    }
    // Send actions to queue
    await sendResultToQueue(context, user, task, objects);
    // Update task
    totalProcessed += elements.length;
    await updateTask(context, task.id, { task_processed_number: totalProcessed });
  };
};

export const buildContainersElementsBundle = async (context, user, containers, elements, withNeighbours, operationType) => {
  const elementIds = new Set();
  const elementStandardIds = new Set();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    elementIds.add(element.internal_id);
    elementStandardIds.add(element.standard_id);
    if (element.fromId) elementIds.add(element.fromId);
    if (element.toId) elementIds.add(element.toId);
  }
  if (withNeighbours) {
    const callback = (relations) => {
      relations.forEach((relation) => {
        elementIds.add(relation.fromId);
        elementIds.add(relation.toId);
        elementIds.add(relation.id);
      });
    };
    const args = { fromOrToId: Array.from(elementIds), baseData: true, callback };
    await fullRelationsList(context, user, ABSTRACT_STIX_CORE_RELATIONSHIP, args);
  }
  // Build limited stix object to limit memory footprint
  const containerOperations = [{
    type: operationType,
    context: {
      field: INPUT_OBJECTS,
      values: Array.from(elementIds)
    }
  }];
  const objects = [];
  for (let i = 0; i < containers.length; i += 1) {
    const container = containers[i];
    objects.push({
      id: container.standard_id,
      type: convertTypeToStixType(container.entity_type),
      object_refs: Array.from(elementStandardIds), // object refs for split ordering
      extensions: {
        [STIX_EXT_OCTI]: {
          ...baseOperationBuilder('KNOWLEDGE_CHANGE', containerOperations, container),
          id: container.internal_id,
          type: container.entity_type
        }
      }
    });
  }
  return objects;
};

const containerOperationCallback = async (context, user, task, containers, operations) => {
  const withNeighbours = operations[0].context.options?.includeNeighbours;
  const operationType = operations[0].type;
  let totalProcessed = task.task_processed_number;
  return async (elements) => {
    const objects = await buildContainersElementsBundle(context, user, containers, elements, withNeighbours, operationType);
    // Send actions to queue
    await sendResultToQueue(context, user, task, objects);
    // Update task
    totalProcessed += elements.length;
    await updateTask(context, task.id, { task_processed_number: totalProcessed });
  };
};

const promoteOperationCallback = async (context, user, task, container) => {
  let totalProcessed = task.task_processed_number;
  return async (elements) => {
    const objects = [];
    const ids = elements.map((e) => e.internal_id);
    const loadedElements = await storeLoadByIdsWithRefs(context, user, ids);
    for (let index = 0; index < loadedElements.length; index += 1) {
      const loadedElement = loadedElements[index];
      // If indicator, promote to observable
      if (loadedElement.entity_type === ENTITY_TYPE_INDICATOR) {
        const indicator = loadedElement;
        const { pattern } = indicator;
        const observables = extractValidObservablesFromIndicatorPattern(pattern);
        for (let obsIndex = 0; obsIndex < observables.length; obsIndex += 1) {
          const observable = observables[obsIndex];
          const observableToCreate = {
            ...R.dissoc('type', observable),
            entity_type: observable.type,
            x_opencti_description: indicator.description ? indicator.description
              : `Simple observable of indicator {${indicator.name || indicator.pattern}}`,
            x_opencti_score: indicator.x_opencti_score,
            createdBy: indicator.createdBy,
            objectMarking: indicator.objectMarking,
            objectOrganization: indicator.objectOrganization,
            objectLabel: indicator.objectLabel,
            externalReferences: indicator.externalReferences,
          };
          observableToCreate.standard_id = generateStandardId(observableToCreate.entity_type, observableToCreate);
          const stixObservable = convertStoreToStix_2_1(observableToCreate);
          objects.push(stixObservable);
          const relationToCreate = {
            from: indicator,
            fromId: indicator.internal_id,
            fromType: indicator.entity_type,
            to: observableToCreate,
            toId: observableToCreate.internal_id,
            toType: observableToCreate.entity_type,
            entity_type: RELATION_BASED_ON,
            relationship_type: RELATION_BASED_ON,
            objectMarking: indicator.objectMarking,
            objectOrganization: indicator.objectOrganization,
          };
          relationToCreate.standard_id = generateStandardId(RELATION_BASED_ON, relationToCreate);
          const stixRelation = convertStoreToStix_2_1(relationToCreate);
          objects.push(stixRelation);
        }
      }
      // If observable, promote to indicator
      if (isStixCyberObservable(loadedElement.entity_type)) {
        const indicatorToCreate = await generateIndicatorFromObservable(context, user, loadedElement, loadedElement);
        indicatorToCreate.entity_type = ENTITY_TYPE_INDICATOR;
        indicatorToCreate.standard_id = generateStandardId(ENTITY_TYPE_INDICATOR, indicatorToCreate);
        const stixIndicator = convertStoreToStix_2_1(indicatorToCreate);
        objects.push(stixIndicator);
        const relationToCreate = {
          from: indicatorToCreate,
          fromId: indicatorToCreate.internal_id,
          fromType: indicatorToCreate.entity_type,
          to: loadedElement,
          toId: loadedElement.internal_id,
          toType: loadedElement.entity_type,
          entity_type: RELATION_BASED_ON,
          relationship_type: RELATION_BASED_ON,
          objectMarking: indicatorToCreate.objectMarking,
          objectOrganization: indicatorToCreate.objectOrganization,
        };
        relationToCreate.standard_id = generateStandardId(RELATION_BASED_ON, relationToCreate);
        const stixRelation = convertStoreToStix_2_1(relationToCreate);
        objects.push(stixRelation);
      }
    }
    const objectRefs = objects.map((object) => object.id);
    if (container) {
      const containerOperations = [{
        type: 'ADD',
        context: {
          field: INPUT_OBJECTS,
          values: objects.map((object) => object.id),
        }
      }];
      objects.push({
        id: container.standard_id,
        type: convertTypeToStixType(container.entity_type),
        object_refs: objectRefs, // object refs for split ordering
        extensions: {
          [STIX_EXT_OCTI]: {
            ...baseOperationBuilder('KNOWLEDGE_CHANGE', containerOperations, container),
            id: container.internal_id,
            type: container.entity_type
          }
        }
      });
    }
    // Send actions to queue
    if (objects.length > 0) {
      await sendResultToQueue(context, user, task, objects);
    } else if (task.task_processed_number === 0) {
      // If no objects are created, we want to mark the work as processed so that the background task doesn't remain stuck in processing state
      await updateProcessedTime(context, user, task.work_id, 'No indicator/observable to generate');
    }

    // Update task
    totalProcessed += elements.length;
    await updateTask(context, task.id, { task_processed_number: totalProcessed });
  };
};

const sharingOperationCallback = async (context, user, task, actionType, operations) => {
  let totalProcessed = task.task_processed_number;
  return async (elements) => {
    const objects = [];
    for (let index = 0; index < elements.length; index += 1) {
      const element = elements[index];
      // in case of container we need to share all inner objects
      // We also need to push a no split bundle directly
      if (isStixDomainObjectContainer(element.entity_type)) {
        const containerObjects = [];
        const sharingElements = await getContainerObjects(context, user, element.internal_id, { all: true });
        const allSharingElements = sharingElements.edges?.map((n) => n.node);
        for (let shareIndex = 0; shareIndex < allSharingElements?.length; shareIndex += 1) {
          await doYield();
          const sharingElement = allSharingElements[shareIndex];
          const sharingElementBundle = buildBundleElement(sharingElement, actionType, operations);
          // We do not want to recursively share elements: we only share elements directly contained in current container
          sharingElementBundle.extensions[STIX_EXT_OCTI].sharing_direct_container = true;
          containerObjects.push(sharingElementBundle);
        }
        // Add the container at the end
        const container = buildBundleElement(element, actionType, operations);
        container.extensions[STIX_EXT_OCTI].sharing_direct_container = true;
        containerObjects.push(container);
        // Send actions to queue
        await sendResultToQueue(context, user, task, containerObjects, { forceNoSplit: true });
      } else {
        // If not a container add in global bundle
        objects.push(buildBundleElement(element, actionType, operations));
      }
    }
    if (objects.length > 0) {
      await sendResultToQueue(context, user, task, objects);
    }
    // Update task
    totalProcessed += elements.length;
    await updateTask(context, task.id, { task_processed_number: totalProcessed });
  };
};

const computeOperationCallback = async (context, user, task, actionType, operations) => {
  // Handle specific case of adding elements in container
  if (actionType === 'KNOWLEDGE_CONTAINER') {
    const containerIds = operations[0].context.values;
    const containers = await internalFindByIds(context, user, containerIds, { baseData: true });
    return containerOperationCallback(context, user, task, containers, operations);
  }
  // Handle specific case of promoting indicator or observable
  if (actionType === ACTION_TYPE_PROMOTE) {
    const { containerId } = operations[0];
    const container = containerId ? await internalLoadById(context, user, containerId, { baseData: true }) : undefined;
    return promoteOperationCallback(context, user, task, container);
  }
  // Handle specific sharing operation, as container must share inner object
  if (isShareAction(actionType) || isUnshareAction(actionType)) {
    return sharingOperationCallback(context, user, task, actionType, operations);
  }
  // If not, return standard callback
  return standardOperationCallback(context, user, task, actionType, operations);
};

const workerTaskHandler = async (context, user, task, actionType, operations) => {
  // Generate the right callback
  const callback = await computeOperationCallback(context, user, task, actionType, operations);
  // Handle queries and list
  if (task.type === TASK_TYPE_QUERY) {
    // Task query will be enlisted step by step except for sharing/un sharing
    await taskQuery(context, user, task, callback);
  }
  if (task.type === TASK_TYPE_LIST) {
    // Task list is enlist in one shot
    await taskList(context, user, task, callback);
  }
  if (task.type === TASK_TYPE_RULE) {
    // Task rule is enlist step by step
    await taskRule(context, user, task, callback);
  }
  return updateTask(context, task.id, { completed: true });
};

// If task was created before task migration to worker, we need to initialize a connector_id and and a work_id for it
const handleTaskMigrationToWorker = async (context, task) => {
  const updatedTask = task;
  if (updatedTask.task_expected_number > 0) {
    if (!updatedTask.connector_id) {
      updatedTask.connector_id = await getBestBackgroundConnectorId(context, SYSTEM_USER);
      await updateTask(context, updatedTask.id, { connector_id: updatedTask.connector_id });
    }
    if (!updatedTask.work_id) {
      const work = await createWorkForBackgroundTask(context, updatedTask.id, updatedTask.connector_id);
      updatedTask.work_id = work.id;
      await updateTask(context, updatedTask.id, { work_id: updatedTask.work_id });
    }
  }
  return updatedTask;
};

const taskHandlerGenerator = (context) => {
  return async (rawTask) => {
    const initTask = { ...rawTask };
    const task = await handleTaskMigrationToWorker(context, initTask);
    const isQueryTask = task.type === TASK_TYPE_QUERY;
    const isListTask = task.type === TASK_TYPE_LIST;
    const isRuleTask = task.type === TASK_TYPE_RULE;
    if (!isQueryTask && !isListTask && !isRuleTask) {
      logApp.error('[OPENCTI-MODULE] Task manager unsupported type', { type: task.type });
      return;
    }
    // endregion
    const startPatch = { last_execution_date: now() };
    await updateTask(context, task.id, startPatch);
    // Fetch the user responsible for the task
    const rawUser = await resolveUserByIdFromCache(context, task.initiator_id);
    const user = { ...rawUser, origin: { user_id: rawUser.id, referer: 'background_task' } };
    logApp.debug(`[OPENCTI-MODULE][TASK-MANAGER] Executing job using userId:${rawUser.id}, for task ${task.internal_id}`);
    const draftID = task.draft_context ?? '';
    const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
    const fullContext = { ...context, draft_context: draftID, user_inside_platform_organization };
    // region MASSIVE WORKER OPERATIONS
    // Current format is not aligned with worker practices
    // We need to reformat the actions to back process support
    // Grouping at the same time to add extra checks
    if (isRuleTask) { // Rescan is not a rule task, but a query one
      const actionType = task.enable ? ACTION_TYPE_RULE_APPLY : ACTION_TYPE_RULE_CLEAR;
      task.actions = [{ type: actionType, context: { rule_id: task.rule } }];
    }
    const actionsGroup = R.groupBy((action) => {
      // Bind global remove
      if (isEmptyField(action.context?.field)) {
        if (action.type === ACTION_TYPE_DELETE) {
          return 'KNOWLEDGE_TRASH';
        }
        if (action.type === ACTION_TYPE_COMPLETE_DELETE) {
          return 'KNOWLEDGE_REMOVE';
        }
      }
      // Support specific container add operation
      if (action.context?.field === 'container-object') {
        return 'KNOWLEDGE_CONTAINER';
      }
      // Support generic knowledge
      if ([ACTION_TYPE_ADD, ACTION_TYPE_REPLACE, ACTION_TYPE_REMOVE].includes(action.type)) {
        return 'KNOWLEDGE_CHANGE';
      }
      // No need for transformation
      return action.type;
    }, task.actions);
    const typeOfActions = Object.keys(actionsGroup);
    for (let typeOfActionIndex = 0; typeOfActionIndex < typeOfActions.length; typeOfActionIndex += 1) {
      const typeOfAction = typeOfActions[typeOfActionIndex];
      throwErrorInDraftContext(context, user, typeOfAction);
      const operations = actionsGroup[typeOfAction];
      logApp.info('[TASK-MANAGER] Executing job through distributed workers');
      await workerTaskHandler(fullContext, user, task, typeOfAction, operations);
    }
  };
};

const tasksHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResources([TASK_MANAGER_KEY], { retryCount: 0 });
    logApp.debug('[OPENCTI-MODULE][TASK-MANAGER] Starting task handler');
    running = true;
    const context = executionContext('task_manager', SYSTEM_USER);
    const tasks = await findTasksToExecute(context);
    const taskHandler = taskHandlerGenerator(context);
    await BluePromise.map(tasks, taskHandler, { concurrency: TASK_CONCURRENCY })
      .catch((error) => logApp.error('[OPENCTI-MODULE][TASK-MANAGER] Task manager error', { cause: error }));
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Task manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Task manager handler error', { cause: e, manager: 'TASK_MANAGER' });
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
      logApp.info('[OPENCTI-MODULE][TASK-MANAGER] Running task manager');
      scheduler = setIntervalAsync(async () => {
        await tasksHandler();
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
      logApp.info('[OPENCTI-MODULE][TASK-MANAGER] Stopping task manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const taskManager = initTaskManager();

export default taskManager;
