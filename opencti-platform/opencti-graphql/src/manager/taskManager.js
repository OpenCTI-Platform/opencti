/* eslint-disable camelcase */
import { v4 as uuidv4 } from 'uuid';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { editAuthorizedMembers } from '../utils/authorizedMembers';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { lockResources } from '../lock/master-lock';
import { storeUpdateEvent } from '../database/redis';
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
  buildQueryFilters,
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
  storeLoadByIdsWithRefs,
  storeLoadByIdWithRefs
} from '../database/middleware';
import { now, utcDate } from '../utils/format';
import { isEmptyField, READ_DATA_INDICES, READ_DATA_INDICES_WITHOUT_INFERRED, UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../database/utils';
import { elList, elPaginate, elUpdate, ES_MAX_CONCURRENCY } from '../database/engine';
import { ForbiddenAccess, FunctionalError, TYPE_LOCK_ERROR, ValidationError } from '../config/errors';
import { ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey, ENTITY_TYPE_CONTAINER, INPUT_OBJECTS, RULE_PREFIX } from '../schema/general';
import { BYPASS, executionContext, getUserAccessRight, MEMBER_ACCESS_RIGHT_ADMIN, RULE_MANAGER_USER, SYSTEM_USER } from '../utils/access';
import { executeRuleApply, executeRuleElementRescan, rulesCleanHandler } from './ruleManager';
import { buildEntityFilters, internalFindByIds, internalLoadById, listAllRelations } from '../database/middleware-loader';
import { getRule } from '../domain/rules';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { generateIndicatorFromObservable, promoteObservableToIndicator } from '../domain/stixCyberObservable';
import { indicatorEditField, promoteIndicatorToObservables } from '../modules/indicator/indicator-domain';
import { askElementEnrichmentForConnector } from '../domain/stixCoreObject';
import { objectOrganization, RELATION_GRANTED_TO, RELATION_OBJECT } from '../schema/stixRefRelationship';
import {
  ACTION_TYPE_COMPLETE_DELETE,
  ACTION_TYPE_DELETE,
  ACTION_TYPE_REMOVE_AUTH_MEMBERS,
  ACTION_TYPE_REMOVE_FROM_DRAFT,
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
import { BackgroundTaskScope, ConnectorType } from '../generated/graphql';
import { ENTITY_TYPE_INTERNAL_FILE } from '../schema/internalObject';
import { deleteFile } from '../database/file-storage';
import { checkUserIsAdminOnDashboard } from '../modules/publicDashboard/publicDashboard-utils';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { findById as findOrganizationById } from '../modules/organization/organization-domain';
import { getDraftContext } from '../utils/draftContext';
import { deleteDraftWorkspace } from '../modules/draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { addFilter } from '../utils/filtering/filtering-utils';
import { getBestBackgroundConnectorId, pushToWorkerForConnector } from '../database/rabbitmq';
import { createWork, updateExpectationsNumber } from '../domain/work';
import { convertStoreToStix, convertTypeToStixType } from '../database/stix-converter';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { RELATION_BASED_ON } from '../schema/stixCoreRelationship';
import { extractValidObservablesFromIndicatorPattern } from '../utils/syntax';
import { generateStandardId } from '../schema/identifier';
import { elRemoveElementFromDraft } from '../database/draft-engine';

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

// region NEW implementation
export const taskRule = async (context, user, task, callback) => {
  const { rule, enable } = task;
  const ruleDefinition = await getRule(context, user, rule);
  if (enable) {
    const { scan } = ruleDefinition;
    const options = { orderMode: 'asc', orderBy: 'updated_at', ...buildEntityFilters(scan.types, scan) };
    const finalOpts = { ...options, connectionFormat: false, callback };
    await elList(context, RULE_MANAGER_USER, READ_DATA_INDICES_WITHOUT_INFERRED, finalOpts);
  } else {
    const filters = {
      mode: 'and',
      filters: [{ key: `${RULE_PREFIX}${rule}`, values: ['EXISTS'] }],
      filterGroups: [],
    };
    const options = { orderMode: 'asc', orderBy: 'updated_at', filters };
    const finalOpts = { ...options, connectionFormat: false, callback };
    await elList(context, RULE_MANAGER_USER, READ_DATA_INDICES, finalOpts);
  }
};
export const taskQuery = async (context, user, task, callback) => {
  const { task_position, task_filters, task_search = null, task_excluded_ids = [], scope, task_order_mode } = task;
  const options = await buildQueryFilters(context, user, task_filters, task_search, task_position, scope, task_order_mode);
  if (task_excluded_ids.length > 0) {
    options.filters = addFilter(options.filters, 'id', task_excluded_ids, 'not_eq');
  }
  const finalOpts = { ...options, connectionFormat: false, callback };
  await elList(context, user, READ_DATA_INDICES, finalOpts);
};
export const taskList = async (context, user, task, callback) => {
  const { task_ids, scope, task_order_mode } = task;
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
    orderMode: task_order_mode || 'desc',
    orderBy: scope === BackgroundTaskScope.Import ? 'lastModified' : 'created_at',
  };
  const elements = await internalFindByIds(context, user, task_ids, options);
  callback(elements);
};
// endregion

export const computeQueryTaskElements = async (context, user, task) => {
  const { actions, task_position, task_filters, task_search = null, task_excluded_ids = [], scope, task_order_mode } = task;
  const processingElements = [];
  // Fetch the information
  // note that the query is filtered to allow only elements with matching confidence level
  const data = await executeTaskQuery(context, user, task_filters, task_search, scope, task_order_mode, task_position);
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
  const { actions, task_position, task_ids, scope, task_order_mode } = task;
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
    orderMode: task_order_mode || 'desc',
    orderBy: scope === BackgroundTaskScope.Import ? 'lastModified' : 'created_at',
    includeDeletedInDraft: true,
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
  } else if (element.entity_type === ENTITY_TYPE_DRAFT_WORKSPACE) {
    await deleteDraftWorkspace(context, user, element.id);
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

const executeRuleClean = async (context, user, actionContext, element) => {
  const { rule } = actionContext;
  await rulesCleanHandler(context, user, [element], [rule]);
};

const executeShare = async (context, user, actionContext, element) => {
  const { values } = actionContext;
  for (let indexCreate = 0; indexCreate < values.length; indexCreate += 1) {
    const target = values[indexCreate];
    const currentGrants = element[buildRefRelationKey(RELATION_GRANTED_TO)] ?? [];
    if (!currentGrants.includes(target) && objectOrganization.isRefExistingForTypes(element.entity_type, ENTITY_TYPE_IDENTITY_ORGANIZATION)) {
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
export const executeRemoveAuthMembers = async (context, user, element) => {
  await editAuthorizedMembers(context, user, {
    entityId: element.id,
    entityType: element.entity_type,
    requiredCapabilities: [BYPASS],
    input: null
  });
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
      || actionType === ACTION_TYPE_UNSHARE_MULTIPLE) {
    throw FunctionalError('Cannot execute this task type in draft', { actionType });
  }
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
          logApp.error('[OPENCTI-MODULE] Task manager index processing error', { cause: err, field, index: valueIndex });
          if (errors.length < MAX_TASK_ERRORS) {
            errors.push({ id: value, message: err.message, reason: err.reason });
          }
        }
      }
    } else { // Classic action, need to be apply on each element
      for (let elementIndex = 0; elementIndex < job.elements.length; elementIndex += 1) {
        const { element } = job.elements[elementIndex];
        try {
          throwErrorInDraftContext(context, user, type);
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
            await executeRuleApply(context, user, actionContext.rule, element.internal_id);
          }
          if (type === ACTION_TYPE_RULE_CLEAR) {
            await executeRuleClean(context, user, actionContext, element);
          }
          if (type === ACTION_TYPE_RULE_ELEMENT_RESCAN) {
            await executeRuleElementRescan(context, user, element);
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
          if (type === ACTION_TYPE_REMOVE_AUTH_MEMBERS) {
            await executeRemoveAuthMembers(context, user, element);
          }
          if (type === ACTION_TYPE_REMOVE_FROM_DRAFT) {
            await elRemoveElementFromDraft(context, user, element);
          }
        } catch (err) {
          logApp.error('[OPENCTI-MODULE] Task manager index processing error', { cause: err, field, index: elementIndex });
          if (errors.length < MAX_TASK_ERRORS) {
            errors.push({ id: element.id, message: `${err.message}${err.data?.reason ? ` - ${err.reason}` : ''}` });
          }
        }
      }
      if (type === ACTION_TYPE_SHARE && containerId) {
        // simulate a create event to update downstream openCTI
        const objectStoreBase = await storeLoadByIdWithRefs(context, user, containerId);
        let organizationNames = '';
        for (let i = 0; i < actionContext.values.length; i += 1) {
          const orgId = actionContext.values[i];
          const organization = await findOrganizationById(context, user, orgId);
          organizationNames += `${organization.name} `;
        }
        const message = `Update ${organizationNames} children in \`Shared with\``;
        const objectStoreBaseModified = { ...objectStoreBase, updated_at: utcDate() };
        await storeUpdateEvent(context, user, objectStoreBase, objectStoreBaseModified, message, { allow_only_modified: true });
      }
    }
  }
  return errors;
};

const createWorkForBackgroundTask = async (context, connectorId) => {
  const connector = { internal_id: connectorId, connector_type: ConnectorType.ExternalImport };
  return createWork(context, SYSTEM_USER, connector, `background task @ ${now()}`, connector.internal_id, { receivedTime: now() });
};

// Worker task handler
// For now only support basic knowledge operations ADD / REPLACE / REMOVE
// Support must be improved to support all operations types.
// 2. ACTION_TYPE_RESTORE
// 8. ACTION_TYPE_REMOVE_AUTH_MEMBERS
const CURRENT_SUPPORT_TASKS = [
  // KNOWLEDGE
  'KNOWLEDGE_CHANGE', 'KNOWLEDGE_REMOVE', 'KNOWLEDGE_TRASH', ACTION_TYPE_MERGE,
  'KNOWLEDGE_CONTAINER', ACTION_TYPE_PROMOTE, ACTION_TYPE_ENRICHMENT,
  // RULES MANAGEMENT
  ACTION_TYPE_RULE_APPLY, ACTION_TYPE_RULE_CLEAR, ACTION_TYPE_RULE_ELEMENT_RESCAN,
  // SHARE / UNSHARE
  ACTION_TYPE_SHARE, ACTION_TYPE_UNSHARE, ACTION_TYPE_SHARE_MULTIPLE, ACTION_TYPE_UNSHARE_MULTIPLE,
  // Access
  ACTION_TYPE_REMOVE_AUTH_MEMBERS
];

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
      const attrKey = schemaRelationsRefDefinition
        .convertDatabaseNameToInputName(element.entity_type, action.context.field);
      return { key: attrKey, value: action.context.values, operation: action.type.toLowerCase() };
    });
  }
  if (actionType === 'KNOWLEDGE_TRASH') {
    baseOperationObject.opencti_operation = 'delete';
  }
  if (actionType === 'KNOWLEDGE_REMOVE') {
    baseOperationObject.opencti_operation = 'delete-force';
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
  // Access
  if (actionType === ACTION_TYPE_REMOVE_AUTH_MEMBERS) {
    baseOperationObject.opencti_operation = 'clear_access_restriction';
  }
  return baseOperationObject;
};

const sendResultToQueue = async (context, user, task, work, connectorId, objects, opts = {}) => {
  // Send actions to queue
  const stixBundle = JSON.stringify({ id: uuidv4(), type: 'bundle', objects });
  const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
  // Only add explicit expectation if the worker will not split anything
  if (objects.length === 1 || opts.forceNoSplit) {
    await updateExpectationsNumber(context, user, work.id, objects.length);
  }
  await pushToWorkerForConnector(connectorId, {
    type: 'bundle',
    applicant_id: user.id,
    content,
    work_id: work.id,
    no_split: opts.forceNoSplit ?? false
  });
  // Update task
  const processedNumber = task.task_processed_number + objects.length;
  await updateTask(context, task.id, { task_processed_number: processedNumber });
};

const shareUnshareExtraOperation = async (context, user, task, actionType, operations) => {
  if (isShareAction(actionType) || isUnshareAction(actionType)) {
    const { containerId } = operations[0];
    if (containerId) {
      const opts = { baseData: true, type: ENTITY_TYPE_CONTAINER };
      const container = await internalLoadById(context, user, containerId, opts);
      if (container) {
        const object = {
          id: container.standard_id,
          type: convertTypeToStixType(container.entity_type),
          ...baseOperationBuilder(actionType, operations, container),
          sharing_direct_container: true,
          extensions: {
            [STIX_EXT_OCTI]: {
              id: container.internal_id,
              type: container.entity_type
            }
          }
        };
        return { forceNoSplit: true, object };
      }
    }
  }
  return { forceNoSplit: false, object: null };
};

const standardOperationCallback = async (context, user, task, actionType, operations) => {
  let work;
  const connectorId = await getBestBackgroundConnectorId(context, user);
  return async (elements) => {
  // Only create work at the first iteration, preventing creating a no work job
    if (!work) {
      work = await createWorkForBackgroundTask(context, connectorId);
      await updateTask(context, task.id, { work_id: work.id });
    }
    // Build limited stix object to limit memory footprint
    const objects = elements.map((e) => ({
      id: e.standard_id,
      type: convertTypeToStixType(e.entity_type),
      ...baseOperationBuilder(actionType, operations, e),
      extensions: {
        [STIX_EXT_OCTI]: {
          id: e.internal_id,
          type: e.entity_type
        }
      }
    }));
    // If share / unshare with container, add the container and force worker to not split the bundle
    const { forceNoSplit, object } = await shareUnshareExtraOperation(context, user, task, actionType, operations);
    if (object) objects.push(object);
    // Send actions to queue
    await sendResultToQueue(context, user, task, work, connectorId, objects, { forceNoSplit });
  };
};

const containerOperationCallback = async (context, user, task, containers, operations) => {
  let work;
  const connectorId = await getBestBackgroundConnectorId(context, user);
  const withNeighbours = operations[0].context.options.includeNeighbours;
  return async (elements) => {
    // Only create work at the first iteration, preventing creating a no work job
    if (!work) {
      work = await createWorkForBackgroundTask(context, connectorId);
      await updateTask(context, task.id, { work_id: work.id });
    }
    const elementIds = new Set();
    const elementStandardIds = new Set();
    for (let index = 0; index < elements.length; index += 1) {
      const element = elements[index];
      elementIds.add(element.internal_id);
      elementStandardIds.add(element.standard_id);
      if (withNeighbours) {
        if (element.fromId) elementIds.add(element.fromId);
        if (element.toId) elementIds.add(element.toId);
        const callback = (relations) => {
          relations.forEach((relation) => {
            elementIds.add(relation.fromId);
            elementIds.add(relation.toId);
          });
        };
        const args = { fromOrToId: elementIds, baseData: true, callback };
        await listAllRelations(context, user, ABSTRACT_STIX_CORE_RELATIONSHIP, args);
      }
    }
    // Build limited stix object to limit memory footprint
    const containerOperations = [{
      type: 'ADD',
      context: {
        field: RELATION_OBJECT,
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
        ...baseOperationBuilder('KNOWLEDGE_CHANGE', containerOperations, container),
        extensions: {
          [STIX_EXT_OCTI]: {
            id: container.internal_id,
            type: container.entity_type
          }
        }
      });
    }
    // Send actions to queue
    await sendResultToQueue(context, user, task, work, connectorId, objects);
  };
};

const promoteOperationCallback = async (context, user, task, container) => {
  let work;
  const connectorId = await getBestBackgroundConnectorId(context, user);
  return async (elements) => {
    // Only create work at the first iteration, preventing creating a no work job
    if (!work) {
      work = await createWorkForBackgroundTask(context, connectorId);
      await updateTask(context, task.id, { work_id: work.id });
    }
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
          const stixObservable = convertStoreToStix(observableToCreate);
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
          const stixRelation = convertStoreToStix(relationToCreate);
          objects.push(stixRelation);
        }
      }
      // If observable, promote to indicator
      if (isStixCyberObservable(loadedElement.entity_type)) {
        const indicatorToCreate = await generateIndicatorFromObservable(context, user, loadedElement, loadedElement);
        indicatorToCreate.entity_type = ENTITY_TYPE_INDICATOR;
        indicatorToCreate.standard_id = generateStandardId(ENTITY_TYPE_INDICATOR, indicatorToCreate);
        const stixIndicator = convertStoreToStix(indicatorToCreate);
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
        const stixRelation = convertStoreToStix(relationToCreate);
        objects.push(stixRelation);
      }
    }
    const objectRefs = objects.map((object) => object.id);
    if (container) {
      const containerOperations = [{
        type: 'ADD',
        context: {
          field: RELATION_OBJECT,
          values: objects.map((object) => object.id),
        }
      }];
      objects.push({
        id: container.standard_id,
        type: convertTypeToStixType(container.entity_type),
        object_refs: objectRefs, // object refs for split ordering
        ...baseOperationBuilder('KNOWLEDGE_CHANGE', containerOperations, container),
        extensions: {
          [STIX_EXT_OCTI]: {
            id: container.internal_id,
            type: container.entity_type
          }
        }
      });
    }
    // Send actions to queue
    await sendResultToQueue(context, user, task, work, connectorId, objects);
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
  // If not, return standard callback
  return standardOperationCallback(context, user, task, actionType, operations);
};

const workerTaskHandler = async (context, user, task, actionType, operations) => {
  // Generate the right callback
  const callback = await computeOperationCallback(context, user, task, actionType, operations);
  // Handle queries and list
  if (task.type === TASK_TYPE_QUERY) {
    await taskQuery(context, user, task, callback);
  }
  if (task.type === TASK_TYPE_LIST) {
    await taskList(context, user, task, callback);
  }
  if (task.type === TASK_TYPE_RULE) {
    await taskRule(context, user, task, callback);
  }
  return updateTask(context, task.id, { completed: true });
};

export const taskHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResources([TASK_MANAGER_KEY], { retryCount: 0 });
    logApp.debug('[OPENCTI-MODULE][TASK-MANAGER] Starting task handler');
    running = true;
    const startingTime = new Date().getMilliseconds();
    const context = executionContext('task_manager', SYSTEM_USER);
    const task = await findTaskToExecute(context);
    // region Task checking
    if (!task) {
      // Nothing to execute.
      logApp.debug('[OPENCTI-MODULE][TASK-MANAGER] No task to execute found, stopping.');
      return;
    }
    const isQueryTask = task.type === TASK_TYPE_QUERY;
    const isListTask = task.type === TASK_TYPE_LIST;
    const isRuleTask = task.type === TASK_TYPE_RULE;
    if (!isQueryTask && !isListTask && !isRuleTask) {
      logApp.error('[OPENCTI-MODULE] Task manager unsupported type', { type: task.type });
      return;
    }
    // endregion
    const draftID = task.draft_context ?? '';
    const fullContext = { ...context, draft_context: draftID };
    const startPatch = { last_execution_date: now() };
    await updateTask(context, task.id, startPatch);
    // Fetch the user responsible for the task
    const rawUser = await resolveUserByIdFromCache(context, task.initiator_id);
    const user = { ...rawUser, origin: { user_id: rawUser.id, referer: 'background_task' } };
    logApp.debug(`[OPENCTI-MODULE][TASK-MANAGER] Executing job using userId:${rawUser.id}, for task ${task.internal_id}`);
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
      // Support generic knowledge§
      if (['ADD', 'REPLACE', 'REMOVE'].includes(action.type)) {
        return 'KNOWLEDGE_CHANGE';
      }
      // No need for transformation
      return action.type;
    }, task.actions);
    const nbTypeOfActions = Object.keys(actionsGroup).length;
    const [actionType, operations] = Object.entries(actionsGroup)[0];
    if (nbTypeOfActions === 1 && CURRENT_SUPPORT_TASKS.includes(actionType)) {
      logApp.info('[TASK-MANAGER] Executing job through distributed workers');
      await workerTaskHandler(fullContext, user, task, actionType, operations);
      return;
    }
    // endregion
    // region MASSIVE BACK OPERATIONS
    let jobToExecute;
    if (isQueryTask) {
      jobToExecute = await computeQueryTaskElements(fullContext, user, task);
    }
    if (isListTask) {
      jobToExecute = await computeListTaskElements(fullContext, user, task);
    }
    if (isRuleTask) {
      jobToExecute = await computeRuleTaskElements(fullContext, user, task);
    }
    // Process the elements (empty = end of execution)
    const processingElements = jobToExecute.elements;
    logApp.debug(`[OPENCTI-MODULE][TASK-MANAGER] Found ${processingElements.length} element(s) to process.`);
    if (processingElements.length > 0) {
      lock.signal.throwIfAborted();
      const errors = await executeProcessing(fullContext, user, jobToExecute, task.scope);
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
    logApp.debug('[OPENCTI-MODULE][TASK-MANAGER] Elements processing done, store task status.', { patch });
    await updateTask(context, task.id, patch);
    const totalTime = new Date().getMilliseconds() - startingTime;
    logApp.info(`[OPENCTI-MODULE][TASK-MANAGER] Task manager done in ${totalTime} ms`);
    // endregion
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
