import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  batchLoader,
  createEntity,
  deleteElementById,
  patchAttribute,
  updateAttribute
} from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import type {
  EditInput,
  QueryNotificationsArgs,
  QueryTriggersActivityArgs,
  QueryTriggersKnowledgeArgs,
  TriggerActivityDigestAddInput,
  TriggerActivityLiveAddInput,
  TriggerDigestAddInput,
  TriggerLiveAddInput,
  TriggerType
} from '../../generated/graphql';
import { TriggerType as TriggerTypeValue } from '../../generated/graphql';
import {
  internalFindByIds,
  internalLoadById,
  listEntitiesPaginated,
  storeLoadById,
} from '../../database/middleware-loader';
import {
  BasicStoreEntityLiveTrigger,
  BasicStoreEntityNotification,
  BasicStoreEntityTrigger,
  ENTITY_TYPE_NOTIFICATION,
  ENTITY_TYPE_TRIGGER,
  NOTIFICATION_NUMBER,
  NotificationAddInput
} from './notification-types';
import { now } from '../../utils/format';
import { elCount, elFindByIds } from '../../database/engine';
import { extractEntityRepresentative, isNotEmptyField, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { ENTITY_FILTERS } from '../../utils/filtering';
import type { BasicStoreEntity, BasicStoreObject, InternalEditInput } from '../../types/store';
import { publishUserAction } from '../../listener/UserActionListener';
import {
  AuthorizedMember,
  getUserAccessRight,
  isUserHasCapability,
  MEMBER_ACCESS_RIGHT_ADMIN,
  MEMBER_ACCESS_RIGHT_EDIT,
  MEMBER_ACCESS_RIGHT_VIEW,
  SETTINGS_SET_ACCESSES,
  SYSTEM_USER,
} from '../../utils/access';
import { ForbiddenAccess, UnsupportedError } from '../../config/errors';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';

// Outcomes

export const batchResolvedInstanceFilters = async (context: AuthContext, user: AuthUser, instanceFiltersIds: string[]) => {
  const instanceIds = instanceFiltersIds.map((u) => (Array.isArray(u) ? u : [u]));
  const allInstanceIds = instanceIds.flat();
  const instanceToFinds = R.uniq(allInstanceIds.filter((u) => isNotEmptyField(u)));
  const instances = await elFindByIds(context, user, instanceToFinds, { toMap: true }) as BasicStoreObject[];
  return instanceIds
    .map((ids) => ids
      .map((id) => [
        id,
        Object.keys(instances).includes(id),
        instances[id] ? extractEntityRepresentative(instances[id]) : '',
      ]));
};

const resolvedInstanceFiltersLoader = batchLoader(batchResolvedInstanceFilters);

// Triggers
// Due to engine limitation we restrict the recipient to only one user for now
const extractUniqRecipient = async (
  context: AuthContext,
  user: AuthUser,
  triggerInput: TriggerDigestAddInput | TriggerLiveAddInput,
  type: TriggerType
): Promise<BasicStoreEntity> => {
  const { recipients } = triggerInput;
  let recipient = user.id;
  if (recipients?.length && recipients?.length === 1) {
    if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
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
  type: TriggerType
): Promise<BasicStoreEntityTrigger> => {
  if (type === TriggerTypeValue.Live && (triggerInput as TriggerLiveAddInput).event_types.length === 0) {
    throw Error('Attribute "trigger_events" of a live trigger should have at least one event.');
  }
  let authorizedMembers;
  const recipient = await extractUniqRecipient(context, user, triggerInput, type);
  const isSelfTrigger = recipient.id === user.id;
  if (recipient.entity_type === ENTITY_TYPE_USER) {
    authorizedMembers = [{ id: recipient.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }];
  } else if (recipient.entity_type === ENTITY_TYPE_GROUP || recipient.entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
    authorizedMembers = [{ id: recipient.id, access_right: MEMBER_ACCESS_RIGHT_VIEW }];
  } else {
    throw UnsupportedError(`Cannot add a recipient with type ${type}`);
  }
  const defaultOpts = {
    trigger_type: type,
    created: now(),
    updated: now(),
    trigger_scope: 'knowledge',
    instance_trigger: type === TriggerTypeValue.Digest ? false : (triggerInput as TriggerLiveAddInput).instance_trigger,
    authorized_members: authorizedMembers,
    authorized_authorities: [SETTINGS_SET_ACCESSES] // Add extra capabilities
  };
  const trigger = { ...triggerInput, ...defaultOpts };
  const created = await createEntity(context, user, trigger, ENTITY_TYPE_TRIGGER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: isSelfTrigger ? 'extended' : 'administration',
    message: `creates ${type} trigger \`${created.name}\` for ${isSelfTrigger ? '`themselves`' : `\`${recipient.name}\``}`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_TRIGGER, input: triggerInput }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].ADDED_TOPIC, created, user);
};

export const addTriggerActivity = async (
  context: AuthContext,
  user: AuthUser,
  triggerInput: TriggerActivityLiveAddInput | TriggerActivityDigestAddInput,
  type: TriggerType
): Promise<BasicStoreEntityTrigger> => {
  const members = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, triggerInput.recipients);
  if (members.length === 0) {
    throw UnsupportedError('Cannot add a activity trigger without recipients');
  }
  const defaultOpts = {
    created: now(),
    updated: now(),
    trigger_scope: 'activity',
    trigger_type: type,
    authorized_members: [...(triggerInput.recipients ?? []).map((r) => ({ id: r, access_right: MEMBER_ACCESS_RIGHT_VIEW }))],
    authorized_authorities: ['SETTINGS'] // Add extra capabilities
  };
  const trigger = { ...triggerInput, ...defaultOpts };
  const created = await createEntity(context, user, trigger, ENTITY_TYPE_TRIGGER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates ${type} activity trigger \`${created.name}\` for ${members.map((m) => `\`${m.name}\``).join(', ')}`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_TRIGGER, input: triggerInput }
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
    const ids = element.authorized_members.map((a) => a.id);
    return internalFindByIds<BasicStoreEntity>(context, user, ids);
  }
  return [];
};

export const triggerEdit = async (context: AuthContext, user: AuthUser, triggerId: string, input: InternalEditInput[]) => {
  const trigger = await triggerGet(context, user, triggerId);
  const userAccessRight = getUserAccessRight(user, trigger);
  if (userAccessRight === null || ![MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN].includes(userAccessRight)) {
    throw ForbiddenAccess();
  }
  if (trigger.trigger_type === 'live') {
    const emptyTriggerEvents = input.filter((editEntry) => editEntry.key === 'event_types' && editEntry.value.length === 0);
    if (emptyTriggerEvents.length > 0) {
      throw Error('Attribute "trigger_events" of a live trigger should have at least one event.');
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
      finalInput.push({ key: 'authorized_members', value });
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
  const adminIds = (trigger.authorized_members ?? [])
    .filter((a: AuthorizedMember) => a.access_right === 'admin')
    .map((a: AuthorizedMember) => a.id);
  const isSelfTrigger = adminIds.length === 1;
  const deleted = await deleteElementById(context, user, triggerId, ENTITY_TYPE_TRIGGER);
  const memberIds = (trigger.authorized_members ?? []).map((a: AuthorizedMember) => a.id);
  const recipients = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, memberIds);
  const recipientNames = recipients.map((r) => r.name);
  await notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].DELETE_TOPIC, deleted, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: isSelfTrigger ? 'extended' : 'administration',
    message: `deletes trigger \`${deleted.name}\` for ${isSelfTrigger ? '`themselves`' : `${recipientNames.map((r) => `\`${r}\``).join(', ')}`}`,
    context_data: { id: triggerId, entity_type: ENTITY_TYPE_TRIGGER, input: deleted }
  });
  return triggerId;
};

export const resolvedInstanceFiltersGet = async (context: AuthContext, user: AuthUser, trigger: BasicStoreEntityLiveTrigger | BasicStoreEntityTrigger) => {
  if (trigger.trigger_type === 'live') {
    const filters = trigger.trigger_type === 'live' ? JSON.parse((trigger as BasicStoreEntityLiveTrigger).filters) : {};
    const instanceFilters = ENTITY_FILTERS.map((n) => filters[n]).filter((el) => el);
    const instanceFiltersIds = instanceFilters.flat().map((instanceFilter) => instanceFilter.id);
    const resolvedInstanceFilters = await resolvedInstanceFiltersLoader.load(instanceFiltersIds, context, user) as [string, boolean, string | undefined][];
    return resolvedInstanceFilters.map((n) => {
      const [id, valid, value] = n;
      return { id, valid, value };
    });
  }
  return [];
};

export const triggersKnowledgeFind = (context: AuthContext, user: AuthUser, opts: QueryTriggersKnowledgeArgs) => {
  // key is a string[] because of the resolver, we have updated the keys
  const finalFilter = [];
  finalFilter.push(...(opts.filters ?? []));
  finalFilter.push({ key: ['trigger_scope'], values: ['knowledge'] });
  const queryArgs = { ...opts, filters: finalFilter };
  return listEntitiesPaginated<BasicStoreEntityTrigger>(context, user, [ENTITY_TYPE_TRIGGER], queryArgs);
};

export const triggersActivityFind = (context: AuthContext, user: AuthUser, opts: QueryTriggersActivityArgs) => {
  const finalFilter = [];
  finalFilter.push(...(opts.filters ?? []));
  finalFilter.push({ key: ['trigger_scope'], values: ['activity'] });
  const queryArgs = { ...opts, includeAuthorities: true, filters: finalFilter };
  return listEntitiesPaginated<BasicStoreEntityTrigger>(context, user, [ENTITY_TYPE_TRIGGER], queryArgs);
};

// region Notifications
export const notificationGet = (context: AuthContext, user: AuthUser, narrativeId: string): BasicStoreEntityNotification => {
  return storeLoadById(context, user, narrativeId, ENTITY_TYPE_NOTIFICATION) as unknown as BasicStoreEntityNotification;
};
export const notificationsFind = (context: AuthContext, user: AuthUser, opts: QueryNotificationsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityNotification>(context, user, [ENTITY_TYPE_NOTIFICATION], opts);
};
export const myNotificationsFind = (context: AuthContext, user: AuthUser, opts: QueryNotificationsArgs) => {
  const queryFilters = [...(opts.filters || []), { key: 'user_id', values: [user.id] }];
  const queryArgs = { ...opts, filters: queryFilters };
  return listEntitiesPaginated<BasicStoreEntityNotification>(context, user, [ENTITY_TYPE_NOTIFICATION], queryArgs);
};
export const myUnreadNotificationsCount = async (context: AuthContext, user: AuthUser, userId = null) => {
  const queryFilters = [{ key: 'user_id', values: [userId ?? user.id] }, { key: 'is_read', values: [false] }];
  const queryArgs = { filters: queryFilters };
  return elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...queryArgs, types: [ENTITY_TYPE_NOTIFICATION] });
};
export const notificationDelete = async (context: AuthContext, user: AuthUser, notificationId: string) => {
  const notification = await notificationGet(context, user, notificationId);
  await deleteElementById(context, user, notificationId, ENTITY_TYPE_NOTIFICATION);
  const unreadNotificationsCount = await myUnreadNotificationsCount(context, user);
  await notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: notification.user_id }, user);
  return notificationId;
};
export const notificationEditRead = async (context: AuthContext, user: AuthUser, notificationId: string, read: boolean) => {
  const { element } = await patchAttribute(context, user, notificationId, ENTITY_TYPE_NOTIFICATION, { is_read: read });
  const unreadNotificationsCount = await myUnreadNotificationsCount(context, user);
  await notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: element.user_id }, user);
  return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].EDIT_TOPIC, element, user);
};
export const addNotification = async (context: AuthContext, user: AuthUser, notification: NotificationAddInput) => {
  const created = await createEntity(context, user, notification, ENTITY_TYPE_NOTIFICATION);
  const unreadNotificationsCount = await myUnreadNotificationsCount(context, user, created.user_id);
  await notify(BUS_TOPICS[NOTIFICATION_NUMBER].EDIT_TOPIC, { count: unreadNotificationsCount, user_id: created.user_id }, user);
  return notify(BUS_TOPICS[ENTITY_TYPE_NOTIFICATION].ADDED_TOPIC, created, user);
};
// endregion
