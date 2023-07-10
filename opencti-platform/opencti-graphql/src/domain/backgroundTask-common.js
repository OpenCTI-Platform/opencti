import * as R from 'ramda';
import { uniq } from 'ramda';
import { ENTITY_TYPE_CASE_TEMPLATE } from '../modules/case/case-template/case-template-types';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_BACKGROUND_TASK } from '../schema/internalObject';
import { now } from '../utils/format';
import { BYPASS, MEMBER_ACCESS_RIGHT_ADMIN, SETTINGS_SET_ACCESSES } from '../utils/access';
import { ABSTRACT_STIX_OBJECT, isKnowledge, KNOWLEDGE_DELETE, KNOWLEDGE_UPDATE } from '../schema/general';
import { ForbiddenAccess } from '../config/errors';
import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_NOTIFICATION } from '../modules/notification/notification-types';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { publishUserAction } from '../listener/UserActionListener';
import { storeLoadById } from '../database/middleware-loader';
import { getParentTypes } from '../schema/schemaUtils';

export const TASK_TYPE_QUERY = 'QUERY';
export const TASK_TYPE_RULE = 'RULE';
export const TASK_TYPE_LIST = 'LIST';

export const ACTION_TYPE_DELETE = 'DELETE';
export const ACTION_TYPE_SHARE = 'SHARE';
export const ACTION_TYPE_UNSHARE = 'UNSHARE';

const areParentTypesKnowledge = (parentTypes) => parentTypes && parentTypes.flat().every((type) => isKnowledge(type));

// check a user has the right to create a list or a query background task
export const checkActionValidity = async (context, user, input, scope, taskType) => {
  const { actions, filters, ids } = input;
  const userCapabilities = R.flatten(user.capabilities.map((c) => c.name.split('_')));
  if (scope === 'KNOWLEDGE') { // 01. Background task of scope Knowledge
    // 1.1. The user should have the capability KNOWLEDGE_UPDATE
    const isAuthorized = userCapabilities.includes(BYPASS) || userCapabilities.includes(KNOWLEDGE_UPDATE);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    const askForDeletion = actions.filter((a) => a.type === ACTION_TYPE_DELETE).length > 0;
    if (askForDeletion) {
      // 1.2. If deletion action available, the user should have the capability KNOWLEDGE_DELETE
      const isDeletionAuthorized = userCapabilities.includes(BYPASS) || userCapabilities.includes(KNOWLEDGE_DELETE);
      if (!isDeletionAuthorized) {
        throw ForbiddenAccess();
      }
    }
    // 1.3. Check the modified entities are of type Knowledge
    if (taskType === TASK_TYPE_QUERY) {
      const parentTypes = JSON.parse(filters).entity_type?.map((n) => getParentTypes(n.id));
      const isNotKnowledges = !areParentTypesKnowledge(parentTypes);
      if (isNotKnowledges) {
        throw ForbiddenAccess(undefined, 'The targeted ids are not knowledges.');
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await Promise.all(ids.map((id) => storeLoadById(context, user, id, ABSTRACT_STIX_OBJECT)));
      const isNotKnowledges = objects.includes(undefined)
        || !areParentTypesKnowledge(objects.map((o) => o.parent_types));
      if (isNotKnowledges) {
        throw ForbiddenAccess(undefined, 'The targeted ids are not knowledges.');
      }
    } else {
      throw Error('A background task should be of type query or list.');
    }
  } else if (scope === 'USER') { // 02. Background task of scope Notification
    // Check the modified entities are Notifications
    // and the user has the right to modify them (= notifications are the ones of the user OR the user has SET_ACCESS capability)
    if (taskType === TASK_TYPE_QUERY) {
      const isNotifications = JSON.parse(filters)?.entity_type?.length > 0
        && JSON.parse(filters).entity_type[0].id === 'Notification';
      if (!isNotifications) {
        throw ForbiddenAccess(undefined, 'The targeted ids are not notifications.');
      }
      const isUserData = JSON.parse(filters)?.user_id?.length > 0
        && JSON.parse(filters).user_id[0].id === user.id;
      const isAuthorized = userCapabilities.includes(BYPASS) || userCapabilities.includes(SETTINGS_SET_ACCESSES) || isUserData;
      if (!isAuthorized) {
        throw ForbiddenAccess();
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await Promise.all(ids.map((id) => storeLoadById(context, user, id, ENTITY_TYPE_NOTIFICATION)));
      const isNotNotifications = objects.includes(undefined);
      if (isNotNotifications) {
        throw ForbiddenAccess(undefined, 'The targeted ids are not notifications.');
      }
      const notificationsUsers = uniq(objects.map((o) => o.user_id));
      const isUserData = notificationsUsers.length === 1 && notificationsUsers.includes(user.id);
      const isAuthorized = userCapabilities.includes(BYPASS) || userCapabilities.includes(SETTINGS_SET_ACCESSES) || isUserData;
      if (!isAuthorized) {
        throw ForbiddenAccess();
      }
    } else {
      throw Error('A background task should be of type query or list.');
    }
  } else { // 03. Background task with an invalid scope
    throw Error('A background task should be of scope Knowledge or User.');
  }
};

export const createDefaultTask = (user, input, taskType, taskExpectedNumber, scope = undefined) => {
  const taskId = generateInternalId();
  let task = {
    id: taskId,
    internal_id: taskId,
    standard_id: generateStandardId(ENTITY_TYPE_BACKGROUND_TASK, input),
    entity_type: ENTITY_TYPE_BACKGROUND_TASK,
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
  if (scope) { // add rights for query tasks and list tasks
    task = {
      ...task,
      scope,
      authorized_members: authorizedMembersForTask(user, scope),
      authorized_authorities: authorizedAuthoritiesForTask(scope),
    };
  }
  return task;
};

const authorizedAuthoritiesForTask = (scope) => {
  switch (scope) {
    case 'KNOWLEDGE':
      return ['KNOWLEDGE_KNUPDATE'];
    case 'USER':
      return [SETTINGS_SET_ACCESSES];
    default:
      return [];
  }
};

const authorizedMembersForTask = (user, scope) => {
  switch (scope) {
    case 'KNOWLEDGE':
    case 'USER':
      return [{ id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];
    default:
      return [];
  }
};

export const createListTask = async (context, user, input) => {
  const { actions, ids, scope } = input;
  await checkActionValidity(context, user, input, scope, TASK_TYPE_LIST);
  const task = createDefaultTask(user, input, TASK_TYPE_LIST, ids.length, scope);
  const listTask = {
    ...task,
    actions,
    task_ids: ids,
  };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: 'creates `background task`',
    context_data: { entity_type: ENTITY_TYPE_BACKGROUND_TASK, input: listTask }
  });
  await elIndex(INDEX_INTERNAL_OBJECTS, listTask);
  return listTask;
};

export const isTaskEnabledEntity = (entityType) => {
  return isStixCoreObject(entityType) || isStixCoreRelationship(entityType) || [ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_CASE_TEMPLATE].includes(entityType);
};
