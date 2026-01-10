import { uniq } from 'ramda';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_USER } from '../schema/internalObject';
import { now } from '../utils/format';
import {
  isOnlyOrgaAdmin,
  isUserHasCapability,
  KNOWLEDGE_KNASKIMPORT,
  KNOWLEDGE_KNUPDATE,
  MEMBER_ACCESS_RIGHT_ADMIN,
  SETTINGS_SET_ACCESSES,
  SETTINGS_SETLABELS,
  SYSTEM_USER,
} from '../utils/access';
import { isKnowledge, KNOWLEDGE_UPDATE } from '../schema/general';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../config/errors';
import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_NOTIFICATION } from '../modules/notification/notification-types';
import { publishUserAction } from '../listener/UserActionListener';
import { internalFindByIds, pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import { getParentTypes } from '../schema/schemaUtils';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_DELETE_OPERATION } from '../modules/deleteOperation/deleteOperation-types';
import { BackgroundTaskScope, Capabilities, ConnectorType, FilterMode } from '../generated/graphql';
import { extractFilterGroupValues, findFiltersFromKey, isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { getDraftContext } from '../utils/draftContext';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { TYPE_FILTER, USER_ID_FILTER } from '../utils/filtering/filtering-constants';
import { createWork } from './work';
import { getBestBackgroundConnectorId } from '../database/rabbitmq';
import { addTelemetryCount, TELEMETRY_COUNT } from '../manager/telemetryManager';

export const TASK_TYPE_QUERY = 'QUERY';
export const TASK_TYPE_RULE = 'RULE';
export const TASK_TYPE_LIST = 'LIST';

export const ACTION_TYPE_ADD = 'ADD';
export const ACTION_TYPE_DELETE = 'DELETE';
export const ACTION_TYPE_REMOVE = 'REMOVE';
export const ACTION_TYPE_REPLACE = 'REPLACE';
export const ACTION_TYPE_RESTORE = 'RESTORE';
export const ACTION_TYPE_MERGE = 'MERGE';
export const ACTION_TYPE_PROMOTE = 'PROMOTE';
export const ACTION_TYPE_ENRICHMENT = 'ENRICHMENT';
export const ACTION_TYPE_COMPLETE_DELETE = 'COMPLETE_DELETE';
export const ACTION_TYPE_SHARE = 'SHARE';
export const ACTION_TYPE_UNSHARE = 'UNSHARE';
export const ACTION_TYPE_SEND_EMAIL = 'SEND_EMAIL';
export const ACTION_TYPE_SHARE_MULTIPLE = 'SHARE_MULTIPLE';
export const ACTION_TYPE_UNSHARE_MULTIPLE = 'UNSHARE_MULTIPLE';
export const ACTION_TYPE_REMOVE_AUTH_MEMBERS = 'REMOVE_AUTH_MEMBERS';
export const ACTION_TYPE_REMOVE_FROM_DRAFT = 'REMOVE_FROM_DRAFT';
export const ACTION_TYPE_ADD_ORGANIZATIONS = 'ADD_ORGANIZATIONS';
export const ACTION_TYPE_REMOVE_ORGANIZATIONS = 'REMOVE_ORGANIZATIONS';
export const ACTION_TYPE_ADD_GROUPS = 'ADD_GROUPS';
export const ACTION_TYPE_REMOVE_GROUPS = 'REMOVE_GROUPS';
export const ACTION_TYPE_RULE_APPLY = 'RULE_APPLY';
export const ACTION_TYPE_RULE_CLEAR = 'RULE_CLEAR';
export const ACTION_TYPE_RULE_ELEMENT_RESCAN = 'RULE_ELEMENT_RESCAN';

const isDeleteRestrictedAction = ({ type }) => {
  return type === ACTION_TYPE_DELETE || type === ACTION_TYPE_RESTORE || type === ACTION_TYPE_COMPLETE_DELETE;
};
const areParentTypesKnowledge = (parentTypes) => parentTypes && parentTypes.flat().every((type) => isKnowledge(type));

// check a user has the right to create a list or a query background task
export const checkActionValidity = async (context, user, input, scope, taskType) => {
  const { actions, filters: baseFilterString, ids } = input;
  // check actions validity
  const replaceActionsFields = actions
    .filter((a) => !a.type || a.type === ACTION_TYPE_REPLACE)
    .map((a) => a.field).filter(Boolean);
  const severalReplaceOnSameKey = replaceActionsFields.length !== uniq(replaceActionsFields).length;
  const replaceAndOtherActionOnSameKey = actions.filter((a) => a.type && a.type !== ACTION_TYPE_REPLACE && replaceActionsFields.includes(a.field)).length > 0;
  if (severalReplaceOnSameKey || replaceAndOtherActionOnSameKey) {
    throw FunctionalError('A single task cannot perform several actions on the same field if one action is a replace.', { data: replaceActionsFields });
  }
  // check rights
  const baseFilterObject = baseFilterString ? JSON.parse(baseFilterString) : undefined;
  const filters = isFilterGroupNotEmpty(baseFilterObject)
    ? (baseFilterObject?.filters ?? [])
    : [];
  const entityTypeFilters = findFiltersFromKey(filters, TYPE_FILTER);
  const entityTypeFiltersValues = entityTypeFilters.map((f) => f.values).flat();
  if (scope === BackgroundTaskScope.Settings) { // 01. Background task of scope Settings
    const isAuthorized = isUserHasCapability(user, SETTINGS_SETLABELS);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
  } else if (scope === BackgroundTaskScope.Knowledge) { // 02. Background task of scope Knowledge
    // 2.1. The user should have the capability KNOWLEDGE_UPDATE
    const isAuthorized = isUserHasCapability(user, KNOWLEDGE_UPDATE);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    const askForDeletionRelatedAction = actions.filter((a) => isDeleteRestrictedAction(a)).length > 0;
    if (askForDeletionRelatedAction) {
      // 2.2. If deletion related action available, the user should have the capability KNOWLEDGE_DELETE
      const isDeletionRelatedActionAuthorized = isUserHasCapability(user, 'KNOWLEDGE_KNUPDATE_KNDELETE');
      if (!isDeletionRelatedActionAuthorized) {
        throw ForbiddenAccess();
      }
    }
    // 2.3. If merge action, the user should have the capability KNOWLEDGE_MERGE
    const askForMergeAction = actions.filter((a) => a.type === ACTION_TYPE_MERGE).length > 0;
    if (askForMergeAction) {
      const isMergeActionAuthorized = isUserHasCapability(user, 'KNOWLEDGE_KNUPDATE_KNMERGE');
      if (!isMergeActionAuthorized) {
        throw ForbiddenAccess();
      }
    }
    // 2.4. Check the targeted entities are of type Knowledge
    if (taskType === TASK_TYPE_QUERY) {
      const acceptedInternalTypes = entityTypeFiltersValues.every((type) => type === ENTITY_TYPE_DELETE_OPERATION || type === ENTITY_TYPE_DRAFT_WORKSPACE);
      const parentTypes = entityTypeFiltersValues.map((n) => getParentTypes(n));
      const isNotKnowledge = (!acceptedInternalTypes && !areParentTypesKnowledge(parentTypes)) || entityTypeFiltersValues.some((type) => type === ENTITY_TYPE_VOCABULARY);
      if (isNotKnowledge) {
        throw ForbiddenAccess('The targeted ids are not knowledge.');
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await internalFindByIds(context, user, ids, { includeDeletedInDraft: true });
      const acceptedInternalTypes = objects.every((o) => o?.entity_type === ENTITY_TYPE_DELETE_OPERATION || o?.entity_type === ENTITY_TYPE_DRAFT_WORKSPACE);
      const isNotKnowledge = objects.includes(undefined)
        || (!acceptedInternalTypes && !areParentTypesKnowledge(objects.map((o) => o.parent_types)))
        || objects.some(({ entity_type }) => entity_type === ENTITY_TYPE_VOCABULARY);
      if (isNotKnowledge) {
        throw ForbiddenAccess('The targeted ids are not knowledge.');
      }
    } else {
      throw UnsupportedError('A background task should be of type query or list.');
    }
  } else if (scope === BackgroundTaskScope.UserNotification) { // 03. Background task of scope UserNotification (i.e. on Notifications)
    // Check the targeted entities are Notifications
    // and the user has the right to modify them (= notifications are the ones of the user OR the user has SET_ACCESS capability)
    if (taskType === TASK_TYPE_QUERY) {
      const isNotifications = entityTypeFilters.length === 1
        && entityTypeFilters[0].values.length === 1
        && entityTypeFilters[0].values[0] === 'Notification';
      if (!isNotifications) {
        throw ForbiddenAccess('The targeted ids are not notifications.');
      }
      const userFilters = findFiltersFromKey(filters, USER_ID_FILTER);
      const isUserData = userFilters.length > 0
        && userFilters[0].values.length === 1
        && userFilters[0].values[0] === user.id;
      const isAuthorized = isUserHasCapability(user, SETTINGS_SET_ACCESSES) || isUserData;
      if (!isAuthorized) {
        throw ForbiddenAccess();
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await Promise.all(ids.map((id) => storeLoadById(context, user, id, ENTITY_TYPE_NOTIFICATION)));
      const isNotNotifications = objects.includes(undefined);
      if (isNotNotifications) {
        throw ForbiddenAccess('The targeted ids are not notifications.');
      }
      const notificationsUsers = uniq(objects.map((o) => o.user_id));
      const isUserData = notificationsUsers.length === 1 && notificationsUsers.includes(user.id);
      const isAuthorized = isUserHasCapability(user, SETTINGS_SET_ACCESSES) || isUserData;
      if (!isAuthorized) {
        throw ForbiddenAccess();
      }
    } else {
      throw UnsupportedError('A background task should be of type query or list.', { taskType });
    }
  } else if (scope === BackgroundTaskScope.User) { // 04. Background task of scope User
    // 2.1. The user should have the capability SETTINGS_SET_ACCESSES
    const isAuthorized = isUserHasCapability(user, SETTINGS_SET_ACCESSES) || isOnlyOrgaAdmin(user);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    // Check the targeted entities are User
    if (taskType === TASK_TYPE_QUERY) {
      const isUsers = entityTypeFilters.length === 1
        && entityTypeFilters[0].values.length === 1
        && entityTypeFilters[0].values[0] === 'User';
      if (!isUsers) {
        throw ForbiddenAccess('The targeted ids are not users.');
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await Promise.all(ids.map((id) => storeLoadById(context, user, id, ENTITY_TYPE_USER)));
      const isNotUsers = objects.includes(undefined);
      if (isNotUsers) {
        throw ForbiddenAccess('The targeted ids are not users.');
      }
    } else {
      throw UnsupportedError('A background task should be of type query or list.', { taskType });
    }
  } else if (scope === BackgroundTaskScope.Import) { // 05. Background task of scope Import (i.e. on files and workbenches in Data/import)
    // The user should have the capability KNOWLEDGE_KNASKIMPORT
    const isAuthorized = isUserHasCapability(user, KNOWLEDGE_KNASKIMPORT);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    // The only operation authorized on these scope is Deletion
    if (!actions.every((a) => a.type === ACTION_TYPE_DELETE)) {
      throw UnsupportedError('Background tasks of scope Import can only be deletions.');
    }
    // Check the targeted entities are files: not needed because the method used only target files
  } else if (scope === BackgroundTaskScope.Dashboard) {
    const isAuthorized = isUserHasCapability(user, Capabilities.ExploreExupdateExdelete);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    if (!actions.every((a) => a.type === ACTION_TYPE_DELETE)) {
      throw UnsupportedError('Background tasks of scope dashboard can only be deletions.');
    }
    if (taskType === TASK_TYPE_QUERY) {
      const isWorkspaces = entityTypeFilters.length === 1
        && entityTypeFilters[0].values.length === 1
        && entityTypeFilters[0].values[0] === ENTITY_TYPE_WORKSPACE;
      const typeValues = extractFilterGroupValues(baseFilterObject, 'type');
      const isDashboards = typeValues.length === 1 && typeValues[0] === 'dashboard';
      if (!isWorkspaces || !isDashboards) {
        throw ForbiddenAccess('The targeted ids are not dashboard.');
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await internalFindByIds(context, user, ids);
      if (objects.some((o) => o.entity_type !== ENTITY_TYPE_WORKSPACE || o.type !== 'dashboard')) {
        throw ForbiddenAccess('The targeted ids are not dashboards.');
      }
    }
  } else if (scope === BackgroundTaskScope.Investigation) {
    const isAuthorized = isUserHasCapability(user, Capabilities.InvestigationInupdateIndelete);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    if (!actions.every((a) => a.type === ACTION_TYPE_DELETE)) {
      throw UnsupportedError('Background tasks of scope investigation can only be deletions.');
    }
    if (taskType === TASK_TYPE_QUERY) {
      const isWorkspaces = entityTypeFilters.length === 1
        && entityTypeFilters[0].values.length === 1
        && entityTypeFilters[0].values[0] === ENTITY_TYPE_WORKSPACE;
      const typeValues = extractFilterGroupValues(baseFilterObject, 'type');
      const isInvestigations = typeValues.length === 1 && typeValues[0] === 'investigation';
      if (!isWorkspaces || !isInvestigations) {
        throw ForbiddenAccess('The targeted ids are not investigations.');
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await internalFindByIds(context, user, ids);
      if (objects.some((o) => o.entity_type !== ENTITY_TYPE_WORKSPACE || o.type !== 'investigation')) {
        throw ForbiddenAccess('The targeted ids are not investigations.');
      }
    }
  } else if (scope === BackgroundTaskScope.PublicDashboard) {
    const isAuthorized = isUserHasCapability(user, Capabilities.ExploreExupdatePublish);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    if (!actions.every((a) => a.type === ACTION_TYPE_DELETE)) {
      throw UnsupportedError('Background tasks of scope Public dashboard can only be deletions.');
    }
    if (taskType === TASK_TYPE_QUERY) {
      const isPublicDashboards = entityTypeFilters.length === 1
        && entityTypeFilters[0].values.length === 1
        && entityTypeFilters[0].values[0] === ENTITY_TYPE_PUBLIC_DASHBOARD;
      if (!isPublicDashboards) {
        throw ForbiddenAccess('The targeted ids are not public dashboards.');
      }
      const dashboards = await pageEntitiesConnection(
        context,
        user,
        [ENTITY_TYPE_WORKSPACE],
        {
          filters: {
            mode: FilterMode.And,
            filters: [{ key: ['type'], values: ['dashboard'] }],
            filterGroups: [],
          },
        },
      );
      // This check is because we base our control on authorized members of the
      // associated custom dashboards and not the public dashboard entity itself.
      // If length === 0, it means the user has access to no custom dashboards and
      // so cannot delete public ones.
      if (dashboards.edges.length === 0) {
        throw ForbiddenAccess('No public dashboards to delete.');
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await internalFindByIds(context, user, ids);
      if (objects.some((o) => o.entity_type !== ENTITY_TYPE_PUBLIC_DASHBOARD)) {
        throw ForbiddenAccess('The targeted ids are not public dashboards.');
      }
    }
  } else if (scope === BackgroundTaskScope.Playbook) {
    const isAuthorized = isUserHasCapability(user, Capabilities.SettingsSetaccesses);
    if (!isAuthorized) {
      throw ForbiddenAccess();
    }
    if (!actions.every((a) => a.type === ACTION_TYPE_DELETE)) {
      throw UnsupportedError('Background tasks of scope Playbook can only be deletions.');
    }
    if (taskType === TASK_TYPE_QUERY) {
      const isPlaybooks = entityTypeFilters.length === 1
        && entityTypeFilters[0].values.length === 1
        && entityTypeFilters[0].values[0] === ENTITY_TYPE_PLAYBOOK;
      if (!isPlaybooks) {
        throw ForbiddenAccess('The targeted ids are not playbooks.');
      }
    } else if (taskType === TASK_TYPE_LIST) {
      const objects = await internalFindByIds(context, user, ids);
      if (objects.some((o) => o.entity_type !== ENTITY_TYPE_PLAYBOOK)) {
        throw ForbiddenAccess('The targeted ids are not playbooks.');
      }
    }
  } else { // Background task with an invalid scope
    throw UnsupportedError('A background task should be of scope: SETTINGS, KNOWLEDGE, USER, IMPORT, DASHBOARD, PUBLIC_DASHBOARD.', { scope });
  }
};

export const createWorkForBackgroundTask = async (context, taskId, connectorId) => {
  const connector = { internal_id: connectorId, connector_type: ConnectorType.ExternalImport };
  const args = { background_task_id: taskId, receivedTime: now() };
  return createWork(context, SYSTEM_USER, connector, `background task @ ${now()}`, connector.internal_id, args);
};

export const createDefaultTask = async (context, user, input, taskType, taskExpectedNumber, scope = undefined) => {
  const taskId = generateInternalId();
  let work_id;
  let connector_id;
  if (taskExpectedNumber > 0) {
    connector_id = await getBestBackgroundConnectorId(context, user);
    const work = await createWorkForBackgroundTask(context, taskId, connector_id);
    work_id = work.id;
  }
  let task = {
    id: taskId,
    internal_id: taskId,
    standard_id: generateStandardId(ENTITY_TYPE_BACKGROUND_TASK, input),
    entity_type: ENTITY_TYPE_BACKGROUND_TASK,
    description: input.description ?? '',
    initiator_id: user.internal_id,
    created_at: now(),
    completed: false,
    // Associated job
    work_id,
    work_completed: false,
    connector_id,
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
      restricted_members: authorizedMembersForTask(user, scope),
      authorized_authorities: authorizedAuthoritiesForTask(scope),
    };
  }

  if (scope === BackgroundTaskScope.User) {
    await addTelemetryCount(TELEMETRY_COUNT.BACKGROUND_TASK_USER);
  }
  return task;
};

const authorizedAuthoritiesForTask = (scope) => {
  switch (scope) {
    case 'SETTINGS':
      return [SETTINGS_SETLABELS];
    case 'KNOWLEDGE':
      return [KNOWLEDGE_KNUPDATE];
    case 'USER':
    case 'USER_NOTIFICATION':
      return [SETTINGS_SET_ACCESSES];
    case 'IMPORT':
      return [KNOWLEDGE_KNASKIMPORT];
    case 'DASHBOARD':
      return [Capabilities.ExploreExupdateExdelete];
    case 'INVESTIGATION':
      return [Capabilities.InvestigationInupdateIndelete];
    case 'PUBLIC_DASHBOARD':
      return [Capabilities.ExploreExupdatePublish];
    default:
      return [];
  }
};

const authorizedMembersForTask = (user, scope) => {
  switch (scope) {
    case 'SETTINGS':
    case 'KNOWLEDGE':
    case 'USER':
    case 'DASHBOARD':
    case 'INVESTIGATION':
    case 'PUBLIC_DASHBOARD':
      return [{ id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];
    default:
      return [];
  }
};

export const createListTask = async (context, user, input) => {
  const { actions, ids, scope } = input;
  await checkActionValidity(context, user, input, scope, TASK_TYPE_LIST);
  const task = await createDefaultTask(context, user, input, TASK_TYPE_LIST, ids.length, scope);
  const listTask = {
    ...task,
    actions,
    task_ids: ids,
    draft_context: getDraftContext(context, user),
  };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: 'creates `background task`',
    context_data: { entity_type: ENTITY_TYPE_BACKGROUND_TASK, input: listTask },
  });
  await elIndex(INDEX_INTERNAL_OBJECTS, listTask);
  return listTask;
};
