import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import type {
  EditInput,
  FilterGroup,
  QueryNotificationsArgs,
  QueryTriggersActivityArgs,
  QueryTriggersKnowledgeArgs,
  TriggerActivityDigestAddInput,
  TriggerActivityLiveAddInput,
  TriggerDigestAddInput,
  TriggerLiveAddInput,
  TriggerType,
} from '../../generated/graphql';
import { TriggerType as TriggerTypeValue } from '../../generated/graphql';
import { internalFindByIds, internalLoadById, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import {
  type BasicStoreEntityNotification,
  type BasicStoreEntityTrigger,
  ENTITY_TYPE_NOTIFICATION,
  ENTITY_TYPE_TRIGGER,
  NOTIFICATION_NUMBER,
  type NotificationAddInput,
  type StoreEntityNotification,
  type StoreEntityTrigger,
} from './notification-types';
import { now } from '../../utils/format';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { BasicStoreEntity, InternalEditInput } from '../../types/store';
import { publishUserAction } from '../../listener/UserActionListener';
import {
  type AuthorizedMember,
  getUserAccessRight,
  isUserHasCapability,
  MEMBER_ACCESS_RIGHT_ADMIN,
  MEMBER_ACCESS_RIGHT_EDIT,
  MEMBER_ACCESS_RIGHT_VIEW,
  VIRTUAL_ORGANIZATION_ADMIN,
  SETTINGS_SET_ACCESSES,
  SYSTEM_USER,
  SETTINGS_SECURITYACTIVITY,
  isOnlyOrgaAdmin,
} from '../../utils/access';
import { AlreadyDeletedError, ForbiddenAccess, UnsupportedError } from '../../config/errors';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { validateFilterGroupForActivityEventMatch } from '../../utils/filtering/filtering-activity-event/activity-event-filtering';
import { validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
import { authorizedMembers } from '../../schema/attribute-definition';

// Triggers
// Due to engine limitation we restrict the recipient to only one user for now
const extractUniqRecipient = async (
  context: AuthContext,
  user: AuthUser,
  triggerInput: TriggerDigestAddInput | TriggerLiveAddInput,
  type: TriggerType,
): Promise<BasicStoreEntity> => {
  const { recipients } = triggerInput;
  let recipient = user.id;
  if (recipients?.length && recipients?.length === 1) {
    if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES) && !isUserHasCapability(user, VIRTUAL_ORGANIZATION_ADMIN)) {
      throw ForbiddenAccess();
    }
    if (recipients?.length && recipients?.length > 1) {
      throw UnsupportedError(`Cannot create ${type} trigger for more than one recipient`);
    }
    [recipient] = recipients;
  }
  return internalLoadById(context, user, recipient);
};

export const addTrigger = async (
  context: AuthContext,
  user: AuthUser,
  triggerInput: TriggerDigestAddInput | TriggerLiveAddInput,
  type: TriggerType,
): Promise<BasicStoreEntityTrigger> => {
  if (type === TriggerTypeValue.Live && (triggerInput as TriggerLiveAddInput).event_types.length === 0) {
    throw UnsupportedError('Attribute "trigger_events" of a live trigger should have at least one event');
  }

  // our stix matching is currently limited, we need to validate the input filters
  const input = triggerInput as TriggerLiveAddInput;
  if (type === TriggerTypeValue.Live && input.filters) {
    const filters = JSON.parse(input.filters) as FilterGroup;
    validateFilterGroupForStixMatch(filters);
  }

  let members;
  const recipient = await extractUniqRecipient(context, user, triggerInput, type);
  const isSelfTrigger = recipient.id === user.id;
  if (recipient.entity_type === ENTITY_TYPE_USER) {
    members = [{ id: recipient.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];
  } else if (recipient.entity_type === ENTITY_TYPE_GROUP || recipient.entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
    members = [{ id: recipient.id, access_right: MEMBER_ACCESS_RIGHT_VIEW }];
  } else {
    throw UnsupportedError(`Cannot add a recipient with type ${type}`);
  }
  const defaultOpts = {
    trigger_type: type,
    created: now(),
    updated: now(),
    created_at: now(),
    updated_at: now(),
    trigger_scope: 'knowledge',
    instance_trigger: type === TriggerTypeValue.Digest ? false : (triggerInput as TriggerLiveAddInput).instance_trigger,
    restricted_members: members,
    authorized_authorities: [SETTINGS_SET_ACCESSES, VIRTUAL_ORGANIZATION_ADMIN], // Add extra capabilities
  };
  const trigger = { ...triggerInput, ...defaultOpts };
  const created = await createEntity(context, user, trigger, ENTITY_TYPE_TRIGGER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: isSelfTrigger ? 'extended' : 'administration',
    message: `creates ${type} trigger \`${created.name}\` for ${isSelfTrigger ? '`themselves`' : `\`${recipient.name}\``}`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_TRIGGER, input: triggerInput },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].ADDED_TOPIC, created, user);
};

export const addTriggerActivity = async (
  context: AuthContext,
  user: AuthUser,
  triggerInput: TriggerActivityLiveAddInput | TriggerActivityDigestAddInput,
  type: TriggerType,
): Promise<BasicStoreEntityTrigger> => {
  const members = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, triggerInput.recipients) as BasicStoreEntity[];
  if (members.length === 0) {
    throw UnsupportedError('Cannot add a activity trigger without recipients');
  }

  // Validate the filter for activity event matching before saving it
  const input = triggerInput as TriggerActivityLiveAddInput;
  if (type === TriggerTypeValue.Live && input.filters) {
    const filters = JSON.parse(input.filters) as FilterGroup;
    validateFilterGroupForActivityEventMatch(filters);
  }

  const defaultOpts = {
    created: now(),
    updated: now(),
    created_at: now(),
    updated_at: now(),
    trigger_scope: 'activity',
    trigger_type: type,
    restricted_members: [...(triggerInput.recipients ?? []).map((r) => ({ id: r, access_right: MEMBER_ACCESS_RIGHT_VIEW }))],
    authorized_authorities: [SETTINGS_SECURITYACTIVITY], // Add extra capabilities
  };
  const trigger = { ...triggerInput, ...defaultOpts };
  const created = await createEntity(context, user, trigger, ENTITY_TYPE_TRIGGER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates ${type} activity trigger \`${created.name}\` for ${members.map((m) => `\`${m.name}\``).join(', ')}`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_TRIGGER, input: triggerInput },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].ADDED_TOPIC, created, user);
};

export const triggerGet = (context: AuthContext, user: AuthUser, triggerId: string): BasicStoreEntityTrigger => {
  return storeLoadById(context, user, triggerId, ENTITY_TYPE_TRIGGER) as unknown as BasicStoreEntityTrigger;
};

// For digest resolutions
export const triggersGet = (context: AuthContext, user: AuthUser, triggerIds: string[]): BasicStoreEntityTrigger[] => {
  return internalFindByIds(context, user, triggerIds) as unknown as BasicStoreEntityTrigger[];
};

export const getTriggerRecipients = async (context: AuthContext, user: AuthUser, element: BasicStoreEntityTrigger) => {
  const access = getUserAccessRight(user, element);
  if (access === MEMBER_ACCESS_RIGHT_ADMIN) {
    const ids = element.restricted_members.map((a) => a.id);
    return internalFindByIds<BasicStoreEntity>(context, user, ids) as Promise<BasicStoreEntity[]>;
  }
  return [];
};

export const triggerEdit = async (context: AuthContext, user: AuthUser, triggerId: string, input: InternalEditInput[]) => {
  const trigger = await triggerGet(context, user, triggerId);
  if (trigger.trigger_type === TriggerTypeValue.Live) {
    const filtersItem = input.find((item) => item.key === 'filters');
    if (filtersItem?.value[0]) {
      const filterGroup = JSON.parse((filtersItem?.value[0]) as string) as FilterGroup;
      // filters need to be validated before save, as we are limited in terms of compatible keys
      // this depends if it's an activity live trigger or knowledge live trigger
      if (trigger.trigger_scope === 'knowledge') {
        validateFilterGroupForStixMatch(filterGroup);
      }
      if (trigger.trigger_scope === 'activity') {
        validateFilterGroupForActivityEventMatch(filterGroup);
      }
    }
  }

  const userAccessRight = getUserAccessRight(user, trigger);
  if (userAccessRight === null || ![MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN].includes(userAccessRight)) {
    throw ForbiddenAccess();
  }
  if (trigger.trigger_type === TriggerTypeValue.Live) {
    const emptyTriggerEvents = input.filter((editEntry) => editEntry.key === 'event_types' && editEntry.value.length === 0);
    if (emptyTriggerEvents.length > 0) {
      throw UnsupportedError('Attribute "trigger_events" of a live trigger should have at least one event');
    }
  }
  const { element: updatedElem } = await updateAttribute(context, user, triggerId, ENTITY_TYPE_TRIGGER, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].EDIT_TOPIC, updatedElem, user);
};

export const triggerActivityEdit = async (context: AuthContext, user: AuthUser, triggerId: string, input: EditInput[]) => {
  const finalInput: InternalEditInput[] = [];
  for (let index = 0; index < input.length; index += 1) {
    const inputElement = input[index];
    if (inputElement.key === 'recipients') {
      const value = (inputElement.value ?? []).map((r) => ({ id: r, access_right: MEMBER_ACCESS_RIGHT_VIEW }));
      finalInput.push({ key: authorizedMembers.name, value });
    } else {
      finalInput.push(inputElement);
    }
  }
  return triggerEdit(context, user, triggerId, finalInput);
};

export const triggerDelete = async (context: AuthContext, user: AuthUser, triggerId: string) => {
  const trigger = await triggerGet(context, user, triggerId);
  const userAccessRight = getUserAccessRight(user, trigger);
  if (userAccessRight !== MEMBER_ACCESS_RIGHT_ADMIN) {
    throw ForbiddenAccess();
  }
  // If user is only organization admin, check if he has access on all targets
  if (isOnlyOrgaAdmin(user)) {
    const memberIds = (trigger.restricted_members ?? []).map((a: AuthorizedMember) => a.id);
    const adminOrganizationIds = (user.administrated_organizations ?? []).map((o) => o.internal_id);
    if (!adminOrganizationIds.every((v) => memberIds.includes(v))) {
      throw ForbiddenAccess();
    }
  }
  const adminIds = (trigger.restricted_members ?? [])
    .filter((a: AuthorizedMember) => a.access_right === 'admin')
    .map((a: AuthorizedMember) => a.id);
  const isSelfTrigger = adminIds.length === 1;
  const deleted = await deleteElementById<StoreEntityTrigger>(context, user, triggerId, ENTITY_TYPE_TRIGGER);
  const memberIds = (trigger.restricted_members ?? []).map((a: AuthorizedMember) => a.id);
  const recipients = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, memberIds) as BasicStoreEntity[];
  const recipientNames = recipients.map((r) => r.name);
  await notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].DELETE_TOPIC, deleted, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: isSelfTrigger ? 'extended' : 'administration',
    message: `deletes trigger \`${deleted.name}\` for ${isSelfTrigger ? '`themselves`' : `${recipientNames.map((r) => `\`${r}\``).join(', ')}`}`,
    context_data: { id: triggerId, entity_type: ENTITY_TYPE_TRIGGER, input: deleted },
  });
  return triggerId;
};
export const triggersKnowledgeFind = (context: AuthContext, user: AuthUser, opts: QueryTriggersKnowledgeArgs) => {
  // key is a string[] because of the resolver, we have updated the keys
  const finalFilter = addFilter(opts.filters, 'trigger_scope', 'knowledge');
  const queryArgs = { ...opts, filters: finalFilter };
  return pageEntitiesConnection<BasicStoreEntityTrigger>(context, user, [ENTITY_TYPE_TRIGGER], queryArgs);
};

export const triggersKnowledgeCount = async (context: AuthContext, opts: QueryTriggersKnowledgeArgs) => {
  const finalFilter = addFilter(opts.filters, 'trigger_scope', 'knowledge');
  const queryArgs = { ...opts, filters: finalFilter, types: [ENTITY_TYPE_TRIGGER] };
  return elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, queryArgs);
};

export const triggersActivityFind = (context: AuthContext, user: AuthUser, opts: QueryTriggersActivityArgs) => {
  const finalFilter = addFilter(opts.filters, 'trigger_scope', 'activity');
  const queryArgs = { ...opts, includeAuthorities: true, filters: finalFilter };
  return pageEntitiesConnection<BasicStoreEntityTrigger>(context, user, [ENTITY_TYPE_TRIGGER], queryArgs);
};

export const triggersFind = (context: AuthContext, user: AuthUser, opts: QueryTriggersActivityArgs) => {
  if (!isUserHasCapability(user, SETTINGS_SECURITYACTIVITY)) {
    // if user doesn't have SETTINGS_SECURITYACTIVITY capabilities, we only return knowledge triggers
    return triggersKnowledgeFind(context, user, opts);
  }
  const queryArgs = { ...opts, includeAuthorities: true };
  return pageEntitiesConnection<BasicStoreEntityTrigger>(context, user, [ENTITY_TYPE_TRIGGER], queryArgs);
};

// region Notifications
export const notificationGet = (context: AuthContext, user: AuthUser, narrativeId: string): BasicStoreEntityNotification => {
  return storeLoadById(context, user, narrativeId, ENTITY_TYPE_NOTIFICATION) as unknown as BasicStoreEntityNotification;
};
export const notificationsFind = (context: AuthContext, user: AuthUser, opts: QueryNotificationsArgs) => {
  const queryArgs = { ...opts, includeAuthorities: true };
  return pageEntitiesConnection<BasicStoreEntityNotification>(context, user, [ENTITY_TYPE_NOTIFICATION], queryArgs);
};
export const myNotificationsFind = (context: AuthContext, user: AuthUser, opts: QueryNotificationsArgs) => {
  const queryFilters = addFilter(opts.filters, 'user_id', user.id);
  const queryArgs = { ...opts, filters: queryFilters };
  return pageEntitiesConnection<BasicStoreEntityNotification>(context, user, [ENTITY_TYPE_NOTIFICATION], queryArgs);
};
export const myUnreadNotificationsCount = async (context: AuthContext, user: AuthUser, userId = null) => {
  const queryFilters = {
    mode: 'and',
    filters: [{ key: 'user_id', values: [userId ?? user.id] }, { key: 'is_read', values: [false] }],
    filterGroups: [],
  };
  const queryArgs = { filters: queryFilters, types: [ENTITY_TYPE_NOTIFICATION] };
  return elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, queryArgs);
};
export const notificationDelete = async (context: AuthContext, user: AuthUser, notificationId: string) => {
  const notification = await notificationGet(context, user, notificationId);
  if (!notification) {
    throw AlreadyDeletedError({ notificationId });
  }
  await deleteElementById(context, user, notificationId, ENTITY_TYPE_NOTIFICATION);
  const unreadNotificationsCount = await myUnreadNotificationsCount(context, user);
  await notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: notification.user_id }, user);
  return notificationId;
};
export const notificationEditRead = async (context: AuthContext, user: AuthUser, notificationId: string, read: boolean) => {
  const { element } = await patchAttribute<StoreEntityNotification>(context, user, notificationId, ENTITY_TYPE_NOTIFICATION, { is_read: read });
  const unreadNotificationsCount = await myUnreadNotificationsCount(context, user);
  await notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: element.user_id }, user);
  return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].EDIT_TOPIC, element, user);
};
export const addNotification = async (context: AuthContext, user: AuthUser, notification: NotificationAddInput) => {
  const members = [{ id: notification.user_id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];
  const notificationWithAuthorized = {
    ...notification,
    restricted_members: members,
    authorized_authorities: [SETTINGS_SET_ACCESSES, VIRTUAL_ORGANIZATION_ADMIN], // Add extra capabilities
  };
  const created = await createEntity(context, user, notificationWithAuthorized, ENTITY_TYPE_NOTIFICATION);
  const unreadNotificationsCount = await myUnreadNotificationsCount(context, user, created.user_id);
  await notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: created.user_id }, user);
  return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].ADDED_TOPIC, created, user);
};
// endregion
