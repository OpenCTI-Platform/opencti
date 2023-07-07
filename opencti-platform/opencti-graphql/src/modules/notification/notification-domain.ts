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
  QueryTriggersArgs,
  TriggerDigestAddInput,
  TriggerLiveAddInput,
  TriggerType
} from '../../generated/graphql';
import { TriggerFilter, TriggerType as TriggerTypeValue } from '../../generated/graphql';
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
import type { BasicStoreEntity, BasicStoreObject } from '../../types/store';
import { publishUserAction } from '../../listener/UserActionListener';
import {
  AuthorizedMember,
  isUserHasCapability,
  MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_VIEW,
  SETTINGS_SET_ACCESSES,
  SYSTEM_USER,
} from '../../utils/access';
import { ForbiddenAccess, UnsupportedError } from '../../config/errors';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../schema/stixDomainObject';

// Outcomes

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
    authorized_members: authorizedMembers,
    created: now(),
    updated: now(),
    instance_trigger: type === TriggerTypeValue.Digest ? false : (triggerInput as TriggerLiveAddInput).instance_trigger,
  };
  const trigger = { ...triggerInput, ...defaultOpts };
  delete trigger.recipients;
  const created = await createEntity(context, user, trigger, ENTITY_TYPE_TRIGGER);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: isSelfTrigger ? 'extended' : 'administration',
    message: `creates ${type} trigger \`${created.name}\` for ${isSelfTrigger ? '`themselves`' : `user \`${recipient.name}\``}`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_TRIGGER, input: triggerInput }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].ADDED_TOPIC, created, user);
};

export const triggerGet = (context: AuthContext, user: AuthUser, triggerId: string): BasicStoreEntityTrigger => {
  return storeLoadById(context, user, triggerId, ENTITY_TYPE_TRIGGER) as unknown as BasicStoreEntityTrigger;
};

export const triggersGet = (context: AuthContext, user: AuthUser, triggerIds: string[]): BasicStoreEntityTrigger[] => {
  return internalFindByIds(context, user, triggerIds) as unknown as BasicStoreEntityTrigger[];
};

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

export const triggerEdit = async (context: AuthContext, user: AuthUser, triggerId: string, input: EditInput[]) => {
  const trigger = await triggerGet(context, user, triggerId);
  if (trigger.trigger_type === 'live') {
    const emptyTriggerEvents = input.filter((editEntry) => editEntry.key === 'event_types' && editEntry.value.length === 0);
    if (emptyTriggerEvents.length > 0) {
      throw Error('Attribute "trigger_events" of a live trigger should have at least one event.');
    }
  }
  const { element: updatedElem } = await updateAttribute(context, user, triggerId, ENTITY_TYPE_TRIGGER, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].EDIT_TOPIC, updatedElem, user);
};
export const triggerDelete = async (context: AuthContext, user: AuthUser, triggerId: string) => {
  const deleted = await deleteElementById(context, user, triggerId, ENTITY_TYPE_TRIGGER);
  // region compute recipients
  const adminIds = (deleted.authorized_members ?? [])
    .filter((a: AuthorizedMember) => a.access_right === 'admin')
    .map((a: AuthorizedMember) => a.id);
  const isSelfTrigger = adminIds.includes(user.id);
  const recipientNames = [];
  if (!isSelfTrigger) {
    const recipients = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, adminIds);
    recipientNames.push(...recipients.map((r) => r.name));
  }
  // region
  await notify(BUS_TOPICS[ENTITY_TYPE_TRIGGER].DELETE_TOPIC, deleted, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: isSelfTrigger ? 'extended' : 'administration',
    message: `deletes trigger \`${deleted.name}\` for ${isSelfTrigger ? '`themselves`' : `user \`${recipientNames.join(', ')}\``}`,
    context_data: { id: triggerId, entity_type: ENTITY_TYPE_TRIGGER, input: deleted }
  });
  return triggerId;
};
export const triggersFind = (context: AuthContext, user: AuthUser, opts: QueryTriggersArgs) => {
  let queryArgs = { ...opts };
  // key is a string[] because of the resolver, we have updated the keys
  const userIdFilter = opts.filters?.find((f) => (f.key as string[]).includes('authorized_members.id'));
  if (userIdFilter) {
    if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
      throw UnsupportedError(`${TriggerFilter.UserIds} filter is only accessible for administration users (set access)`);
    }
    queryArgs = {
      ...queryArgs,
      adminBypassUserAccess: true
    };
  }
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
