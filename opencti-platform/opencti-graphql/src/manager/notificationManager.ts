import * as R from 'ramda';
import * as jsonpatch from 'fast-json-patch';
import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import type { Moment } from 'moment';
import { type SizedNotifEvent, type StreamProcessor } from '../database/stream/stream-utils';
import { fetchRangeNotifications, storeNotificationEvent, createStreamProcessor } from '../database/stream/stream-handler';
import { DIGEST_DELIVERY_CLAIM_MS } from '../database/digest-delivery-timing';
import {
  redisAddChangeDigestJobs,
  redisAreDigestDeliveriesConfirmed,
  redisCountChangeDigestJobAttempt,
  redisExpireChangeDigestJobs,
  redisGetChangeDigestJobAttempts,
  redisGetChangeDigestJobs,
  redisGetChangeDigestWatermarks,
  redisGetManagerEventState,
  redisIsChangeDigestJobDue,
  redisRemoveChangeDigestJob,
  redisRescheduleChangeDigestJob,
  redisSetChangeDigestWatermarks,
  redisSetManagerEventState,
} from '../database/redis';
import { lockResources } from '../lock/master-lock';
import conf, { booleanConf, logApp, ACCOUNT_STATUS_ACTIVE } from '../config/conf';
import { FunctionalError, TYPE_LOCK_ERROR } from '../config/errors';
import { executionContext, INTERNAL_USERS, isUserCanAccessStixElement, isUserCanAccessStreamUpdateEvent, isUserInPlatformOrganization, SYSTEM_USER } from '../utils/access';
import type { DataEvent, SseEvent, StreamNotifEvent, UpdateEvent } from '../types/event';
import type { AuthContext, AuthUser, UserOrigin } from '../types/user';
import { utcDate } from '../utils/format';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../database/utils';
import type { StixCoreObject, StixId, StixObject, StixRelationshipObject } from '../types/stix-2-1-common';
import {
  type BasicStoreEntityDigestTrigger,
  type BasicStoreEntityLiveTrigger,
  type BasicStoreEntityTrigger,
  ENTITY_TYPE_TRIGGER,
} from '../modules/notification/notification-types';
import { resolveFiltersMapForUser } from '../utils/filtering/filtering-resolution';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { OPENCTI_ADMIN_UUID, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';
import { extractStixRepresentative, extractStixRepresentativeForUser } from '../database/stix-representative';
import type { StixRelation, StixSighting } from '../types/stix-2-1-sro';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import type { FilterEventContext } from '../utils/filtering/boolean-logic-engine';
import { replaceFilterKey } from '../utils/filtering/filtering-utils';
import { CONNECTED_TO_INSTANCE_FILTER, CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER } from '../utils/filtering/filtering-constants';
import { buildFilterEventContext } from './playbookManager/playbookManagerUtils';
import { DigestPeriod, type FilterGroup, TriggerEventType, TriggerType } from '../generated/graphql';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import type { Representative } from '../types/store';
import type { BasicStoreSettings } from '../types/settings';
import { type BasicStoreEntityNotifier, ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { NOTIFIER_CONNECTOR_WEBHOOK } from '../modules/notifier/notifier-statics';
import { InterruptibleTimer } from './interruptible-timer';
import { memoize } from '../utils/memoize';
import { buildChangeDigestData, type ChangeDigestTrigger, TRIGGER_TYPE_CHANGE_DIGEST } from '../modules/timeMachine/timeMachine-changeDigest';
import { createBoundedJobQueue } from '../modules/timeMachine/timeMachine-jobQueue';
import { resolveChangeDigestLocale } from '../modules/timeMachine/timeMachine-changeDigest-messages';
import { addChangeDigestSentCount } from './telemetryManager';

const NOTIFICATION_LIVE_KEY = conf.get('notification_manager:lock_live_key');
const NOTIFICATION_DIGEST_KEY = conf.get('notification_manager:lock_digest_key');
const NOTIFICATION_MANAGER_NAME = 'notification_manager';
export const EVENT_NOTIFICATION_VERSION = '1';
// Hard cap on the cumulative byte size of the notification events aggregated into a single digest. The
// notification stream can hold a very large number of events (e.g. a broad live trigger during a massive
// ingest) and individual events vary a lot in size, so the digest is bounded by the total bytes retained
// rather than by a raw event count. Beyond this size the digest content is truncated and a warning is
// logged. Configurable (in bytes) through notification_manager:max_digest_content_size.
export const DEFAULT_MAX_DIGEST_CONTENT_SIZE = 500 * 1024 * 1024; // 500 MB
const MAX_DIGEST_CONTENT_SIZE = conf.get('notification_manager:max_digest_content_size') || DEFAULT_MAX_DIGEST_CONTENT_SIZE;
const CRON_SCHEDULE_TIME = 60000; // 1 minute
const STREAM_SCHEDULE_TIME = 10000;
export const TRIGGER_EVENT_TYPES_VALUES = Object.values(TriggerEventType);
export const TRIGGER_TYPE_VALUES = Object.values(TriggerType);
export const DIGEST_PERIOD_VALUES = Object.values(DigestPeriod);
export const TRIGGER_SCOPE_VALUES = ['knowledge', 'activity'];
export const REQUEST_SHARE_ACCESS_INFO_TYPE = 'Request sharing';

export interface ResolvedTrigger {
  users: Array<AuthUser>;
  trigger: BasicStoreEntityTrigger;
}

export interface ResolvedLive {
  users: Array<AuthUser>;
  trigger: BasicStoreEntityLiveTrigger;
}

export interface ResolvedDigest {
  users: Array<AuthUser>;
  trigger: BasicStoreEntityDigestTrigger;
}

export interface NotificationUser {
  user_id: string;
  user_email: string;
  notifiers: Array<string>;
  user_service_account: boolean;
}

export interface KnowledgeNotificationEvent extends StreamNotifEvent {
  type: 'live';
  targets: Array<{ user: NotificationUser; type: string; message: string }>;
  data: StixObject;
  streamMessage?: string;
  origin: Partial<UserOrigin>;
}

export interface ActivityNotificationEvent extends StreamNotifEvent {
  type: 'live';
  targets: Array<{ user: NotificationUser; type: string; message: string }>;
  data: Partial<{ id: string }>;
  origin: Partial<UserOrigin>;
}

export interface ActionNotificationEvent extends StreamNotifEvent {
  type: 'action';
  targets: Array<{ user: NotificationUser; type: string; message: string }>;
  data: { id: StixId | null; representative: Representative };
  origin: Partial<UserOrigin>;
}

// The receipt of a digest delivered through one notifier
export const toDigestDeliveryReceipt = (deliveryKey: string, notifierId: string) => `${deliveryKey}|${notifierId}`;

export interface DigestEvent extends StreamNotifEvent {
  type: 'digest';
  target: NotificationUser;
  playbook_source?: string;
  // Set when the same digest can be stored more than once (a change digest stored again until every notifier received
  // it): delivered once per key and notifier
  delivery_key?: string;
  data: Array<{ notification_id: string; instance: StixObject; type: string; message: string; origin?: Partial<UserOrigin>; streamMessage?: string }>;
}

export const isLiveKnowledge = (n: ResolvedTrigger): n is ResolvedLive => {
  return n.trigger.trigger_scope === 'knowledge' && n.trigger.trigger_type === 'live';
};

export const isDigest = (n: ResolvedTrigger): n is ResolvedDigest => {
  return n.trigger.trigger_type === 'digest';
};

export const isNotificationRecipientActive = (user: AuthUser): boolean => {
  // Account expiration date reached
  if (user.account_lock_after_date && utcDate().isAfter(utcDate(user.account_lock_after_date))) {
    return false;
  }
  // Account not active (disabled / inactive / expired status)
  return user.account_status === ACCOUNT_STATUS_ACTIVE;
};

const generateAssigneeTrigger = (user: AuthUser) => {
  const filters = {
    mode: 'or',
    filters: [
      { key: ['objectAssignee'], values: [user.internal_id], operator: 'eq', mode: 'or' },
      { key: ['objectParticipant'], values: [user.internal_id], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  };
  return {
    internal_id: `default-trigger-${user.id}`,
    name: 'Default Trigger for Assignee/Participant',
    trigger_type: 'live',
    trigger_scope: 'knowledge',
    event_types: TRIGGER_EVENT_TYPES_VALUES,
    notifiers: user.personal_notifiers,
    filters: JSON.stringify(filters),
    instance_trigger: false,
    restricted_members: [],
  } as unknown as BasicStoreEntityLiveTrigger;
};

export const platformNotification = (user: { id: string }) => `platform-notification-${user.id}`;
const generatePlatformNotificationTrigger = (user: AuthUser) => {
  return {
    internal_id: platformNotification(user),
    name: 'Platform',
    trigger_type: 'live',
    trigger_scope: 'internal',
    event_types: TRIGGER_EVENT_TYPES_VALUES,
    notifiers: user.personal_notifiers,
    instance_trigger: false,
    restricted_members: [],
  } as unknown as BasicStoreEntityLiveTrigger;
};

// For now only for RFI request access creation
const generateRequestAccessAuthorizeTrigger = (user: AuthUser) => {
  const filters = {
    mode: 'and',
    filters: [
      // /!\ objectAuthorized is a specific filter only worker in STIX
      // ONLY to use internally for this specific feature.
      // Any other usage / modification on this required a tech lead validation
      { key: ['objectAuthorized'], values: [user], operator: 'eq', mode: 'or' },
      { key: ['entity_type'], values: [ENTITY_TYPE_CONTAINER_CASE_RFI], operator: 'eq', mode: 'or' },
      { key: ['information_types'], values: [REQUEST_SHARE_ACCESS_INFO_TYPE], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  };
  return {
    internal_id: `default-rfi-trigger-${user.id}`,
    name: 'Request sharing',
    trigger_type: 'live',
    trigger_scope: 'knowledge',
    event_types: ['create'],
    notifiers: user.personal_notifiers,
    raw_filters: filters,
    instance_trigger: false,
    restricted_members: [],
  } as unknown as BasicStoreEntityLiveTrigger;
};

export const getNotifications = async (context: AuthContext): Promise<Array<ResolvedTrigger>> => {
  const triggers = await getEntitiesListFromCache<BasicStoreEntityTrigger>(context, SYSTEM_USER, ENTITY_TYPE_TRIGGER);
  // Exclude inactive/expired/disabled accounts: they must no longer receive any notification.
  const platformUsers = (await getEntitiesListFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER))
    .filter(isNotificationRecipientActive);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const isAssigneeAutoTriggerEnabled = settings.platform_notifier_auto_trigger_assignee ?? true;
  const notificationTriggers = [];
  // nativeTriggers
  for (let index = 0; index < platformUsers.length; index += 1) {
    const user = platformUsers[index];
    if (isAssigneeAutoTriggerEnabled) {
      notificationTriggers.push({ users: [user], trigger: generateAssigneeTrigger(user) });
    }
    notificationTriggers.push({ users: [user], trigger: generatePlatformNotificationTrigger(user) });
    if (user.id !== OPENCTI_ADMIN_UUID) { // Admin is a fallback in current alerting on RFI request access creation.
      notificationTriggers.push({ users: [user], trigger: generateRequestAccessAuthorizeTrigger(user) });
    }
  }
  // definedTriggers
  for (let index = 0; index < triggers.length; index += 1) {
    const trigger = triggers[index];
    const triggerAuthorizedMembersIds = trigger.restricted_members?.map((member) => member.id) ?? [];
    const usersFromGroups = platformUsers.filter((user) => user.groups.map((g) => g.internal_id)
      .some((id: string) => triggerAuthorizedMembersIds.includes(id)));
    const usersFromOrganizations = platformUsers.filter((user) => user.organizations.map((g) => g.internal_id)
      .some((id: string) => triggerAuthorizedMembersIds.includes(id)));
    const usersFromIds = platformUsers.filter((user) => triggerAuthorizedMembersIds.includes(user.id));
    const withoutInternalUsers = [...usersFromOrganizations, ...usersFromGroups, ...usersFromIds]
      .filter((u) => INTERNAL_USERS[u.id] === undefined);
    const users = R.uniqBy(R.prop('id'), withoutInternalUsers);
    notificationTriggers.push({ users, trigger });
  }
  return notificationTriggers;
};

export const getLiveNotifications = async (context: AuthContext): Promise<Array<ResolvedLive>> => {
  const liveNotifications = await getNotifications(context);
  return liveNotifications.filter(isLiveKnowledge);
};

export const isTimeTrigger = (digest: ResolvedDigest, baseDate: Moment): boolean => {
  const now = baseDate.clone().startOf('minutes'); // 2022-11-25T19:11:00.000Z
  const { trigger } = digest;
  const triggerTime = trigger.trigger_time;
  switch (trigger.period) {
    case 'hour': {
      // Need to check if time is aligned on the perfect hour
      const nowHourAlign = now.clone().startOf('hours');
      return now.isSame(nowHourAlign);
    }
    case 'day': {
      // Need to check if time is aligned on the day hour (like 19:11:00.000Z)
      const dayTime = `${now.clone().format('HH:mm:ss.SSS')}Z`;
      return triggerTime === dayTime;
    }
    case 'week': {
      // Need to check if time is aligned on the week hour (like 1-19:11:00.000Z)
      // 1 being Monday and 7 being Sunday.
      const weekTime = `${now.clone().isoWeekday()}-${now.clone().format('HH:mm:ss.SSS')}Z`;
      return triggerTime === weekTime;
    }
    case 'month': {
      // Need to check if time is aligned on the month hour (like 22-19:11:00.000Z)
      const monthTime = `${now.clone().date()}-${now.clone().format('HH:mm:ss.SSS')}Z`;
      return triggerTime === monthTime;
    }
    default:
      return false;
  }
};

/**
 * The most recent minute at or before baseDate at which isTimeTrigger accepts the digest, undefined when its trigger
 * time is malformed or (monthly, on a day missing from the last twelve months) never matches.
 */
export const lastDigestDueDate = (digest: ResolvedDigest, baseDate: Moment): Moment | undefined => {
  const now = baseDate.clone().utc().startOf('minutes');
  const { trigger } = digest;
  if (trigger.period === 'hour') {
    return now.clone().startOf('hours');
  }
  // `HH:mm:ss.SSSZ` for a day, `<weekday or day of month>-HH:mm:ss.SSSZ` for a week or a month
  const time = /^(?:(\d{1,2})-)?(\d{2}):(\d{2})/.exec(trigger.trigger_time ?? '');
  if (!time || (trigger.period !== 'day' && time[1] === undefined)) {
    return undefined;
  }
  const day = Number(time[1]);
  const at = (date: Moment) => date.clone().hours(Number(time[2])).minutes(Number(time[3]));
  let candidate: Moment | undefined;
  if (trigger.period === 'day') {
    candidate = at(now);
    if (candidate.isAfter(now)) candidate.subtract(1, 'days');
  } else if (trigger.period === 'week') {
    candidate = at(now.clone().isoWeekday(day));
    if (candidate.isAfter(now)) candidate.subtract(1, 'weeks');
  } else if (trigger.period === 'month') {
    for (let months = 0; months <= 12 && !candidate; months += 1) {
      const month = now.clone().startOf('months').subtract(months, 'months');
      const date = day <= month.daysInMonth() ? at(month.date(day)) : undefined;
      if (date && !date.isAfter(now)) candidate = date;
    }
  }
  return candidate && isTimeTrigger(digest, candidate) ? candidate : undefined;
};

export const getDigestNotifications = async (context: AuthContext, baseDate: Moment): Promise<Array<ResolvedDigest>> => {
  const notifications = await getNotifications(context);
  return notifications.filter(isDigest).filter((digest) => isTimeTrigger(digest, baseDate));
};

export const convertToNotificationUser = (user: AuthUser, notifiers: Array<string>): NotificationUser => {
  return {
    user_id: user.internal_id,
    user_email: user.user_email,
    user_service_account: user.user_service_account ? user.user_service_account : false,
    notifiers,
  };
};

// indicates if a relation from/to contains an instance that is in an instances map
export const isRelationFromOrToMatchFilters = (
  listenedInstanceIdsMap: Map<string, StixObject>,
  instance: StixRelation | StixSighting,
) => {
  const stixIdsToSearch = [];
  if (instance.type === STIX_TYPE_SIGHTING) {
    stixIdsToSearch.push((instance as StixSighting).sighting_of_ref, ...(instance as StixSighting).where_sighted_refs);
  } else if (instance.type === STIX_TYPE_RELATION) {
    stixIdsToSearch.push((instance as StixRelation).source_ref, (instance as StixRelation).target_ref);
  }

  for (const value of listenedInstanceIdsMap.values()) {
    if (stixIdsToSearch.includes(value.id)) {
      return true;
    }
  }
  return false;
};

// keep only the refs event ids that are in the map of the listened instances
const filterInstancesByRefEventIds = (
  listenedInstanceIdsMap: Map<string, StixObject>,
  refsEventIds: string[],
) => {
  const instances: StixObject[] = [];
  refsEventIds.forEach((refId) => {
    const instance = listenedInstanceIdsMap.get(refId);
    if (instance) {
      instances.push(instance);
    }
  });
  return instances;
};

// generate an array of the instances that are in patch/reverse_patch and in the map of the listened instances
// with the indication, for each instance, if there are in the patch ('added in') or in the reverse_patch ('removed from')
export const filterUpdateInstanceIdsFromUpdatePatch = (
  listenedInstanceIdsMap: Map<string, StixObject>,
  updatePatch: { patch: jsonpatch.Operation[]; reverse_patch: jsonpatch.Operation[] },
) => {
  const addedIds = updatePatch.patch
    .map((n) => (n as { path: string; value: string[] }).value)
    .flat()
    .filter((n) => n);
  const removedIds = updatePatch.reverse_patch
    .map((n) => (n as { path: string; value: string[] }).value)
    .flat()
    .filter((n) => n);
  const instances: { instance: StixCoreObject; action: string }[] = [];
  addedIds.forEach((id) => {
    if (listenedInstanceIdsMap.has(id)) {
      instances.push({
        instance: listenedInstanceIdsMap.get(id) as StixCoreObject,
        action: 'added in',
      });
    }
  });
  removedIds.forEach((id) => {
    if (listenedInstanceIdsMap.has(id)) {
      instances.push({
        instance: listenedInstanceIdsMap.get(id) as StixCoreObject,
        action: 'removed from',
      });
    }
  });
  return instances;
};

const eventTypeTranslater = (
  isPreviousMatch: boolean,
  isCurrentlyMatch: boolean,
  currentType: string,
) => {
  if (isPreviousMatch && !isCurrentlyMatch) { // No longer visible
    return EVENT_TYPE_DELETE;
  }
  if (!isPreviousMatch && isCurrentlyMatch) { // Newly visible
    return EVENT_TYPE_CREATE;
  }
  return currentType;
};

const eventTypeTranslaterForSideEvents = async (
  context: AuthContext,
  user: AuthUser,
  isPreviousMatch: boolean,
  isCurrentlyMatch: boolean,
  currentType: string,
  previousInstance: StixCoreObject | StixRelationshipObject,
  instance: StixCoreObject | StixRelationshipObject,
  listenedInstanceIdsMap: Map<string, StixObject>,
  updatePatch?: { patch: jsonpatch.Operation[]; reverse_patch: jsonpatch.Operation[] },
) => {
  // 1. case update, we should check the updatePatch content
  if (currentType === EVENT_TYPE_UPDATE && updatePatch) {
    // 1.a. we should first check if the visibility of the instance has changed for the user
    // (to deal with cases of update of both a ref linked to rights (markings/granted_refs) and sth else)
    const previouslyVisible = await isUserCanAccessStixElement(context, user, previousInstance);
    const currentlyVisible = await isUserCanAccessStixElement(context, user, instance);
    // - the visiblity has changed: display a changing of rights, don't take the eventual changed refs into account
    if (previouslyVisible !== currentlyVisible) {
      return eventTypeTranslater(isPreviousMatch, isCurrentlyMatch, currentType); // case modification of rights (newly/no more visible)
    }
    // - the visibility has not changed: eventually display an update of refs (-> go to case 1.b.)
    // 1.b. update of a ref without rights modification
    const listenedInstancesInPatchIds = filterUpdateInstanceIdsFromUpdatePatch(listenedInstanceIdsMap, updatePatch);
    if (listenedInstancesInPatchIds.length > 0) { // update of a ref that is in the listened instances
      return EVENT_TYPE_UPDATE;
    }
  }
  // 2. case modification of rights (newly/no more visible)
  return eventTypeTranslater(isPreviousMatch, isCurrentlyMatch, currentType);
};

// generate a notification message for an instance
// taking the user rights into account in case of a relationship (from/to restricted or not)
export const generateNotificationMessageForInstance = async (
  context: AuthContext,
  user: AuthUser,
  instance: StixObject | StixRelationshipObject,
) => {
  const instanceRepresentative = await extractStixRepresentativeForUser(context, user, instance);
  return `[${instance.type.toLowerCase()}] ${instanceRepresentative}`;
};

// generate a notification message with an instance and refs - case creation/deletion
export const generateNotificationMessageForInstanceWithRefs = async (
  context: AuthContext,
  user: AuthUser,
  instance: StixCoreObject | StixRelationshipObject,
  refsInstances: StixObject[],
) => {
  const mainInstanceMessage = await generateNotificationMessageForInstance(context, user, instance);
  return `${mainInstanceMessage} containing ${refsInstances.map((ref) => `[${ref.type.toLowerCase()}] ${extractStixRepresentative(ref)}`)}`;
};

// generate a notification message with an instance and refs - case update
export const generateNotificationMessageForInstanceWithRefsUpdate = async (
  context: AuthContext,
  user: AuthUser,
  instance: StixCoreObject | StixRelationshipObject,
  refsInstances: { instance: StixObject; action: string }[],
) => {
  const mainInstanceMessage = await generateNotificationMessageForInstance(context, user, instance);
  const groupedRefsInstances = Object.values(R.groupBy((ref) => ref.action, refsInstances)); // refs instances grouped by notification message
  return `${
    groupedRefsInstances
      .map((refsGroup) => `${
        (refsGroup || [])
          .map((ref) => `[${ref.instance.type.toLowerCase()}] ${extractStixRepresentative(ref.instance)}`)
      } ${(refsGroup || [])[0]?.action ?? 'unknown'} ${mainInstanceMessage}`)
  }`;
};

// generate the message to display in the notification for filtered instance trigger side events
const generateNotificationMessageForFilteredSideEvents = async (
  context: AuthContext,
  user: AuthUser,
  data: StixCoreObject | StixRelationshipObject,
  frontendFilters: FilterGroup,
  translatedType: string,
  updatePatch?: { patch: jsonpatch.Operation[]; reverse_patch: jsonpatch.Operation[] },
  previousData?: StixCoreObject | StixRelationshipObject,
) => {
  // Get ids from the user trigger filters that user has access to
  const listenedInstanceIdsMap = await resolveFiltersMapForUser(context, user, frontendFilters);
  // -- 01. Notification for relationships (creation/deletion/newly visible/no more visible)
  if ([STIX_TYPE_RELATION, STIX_TYPE_SIGHTING].includes(data.type) // the event is a relationship
    && isRelationFromOrToMatchFilters(listenedInstanceIdsMap, data as StixRelation | StixSighting) // and the relationship from/to contains an instance of the trigger filters
    && translatedType !== EVENT_TYPE_UPDATE // if displayed type is update, we should have notifications in case a listened instance is in the patch (= case 1.2.)
  ) {
    // User should be notified of the relationship creation / deletion / newly visible / no more visible
    return generateNotificationMessageForInstance(context, user, data);
  }
  // -- 02. translatedType = update (i.e. event type = update that modify a listened ref and doesn't modify the rights)
  if (translatedType === EVENT_TYPE_UPDATE) {
    if (!updatePatch) {
      throw FunctionalError('An event of type update should have an update patch');
    }
    const listenedInstancesInPatchIds = filterUpdateInstanceIdsFromUpdatePatch(listenedInstanceIdsMap, updatePatch);
    if (listenedInstancesInPatchIds.length > 0) { // 2.a.--> It's the patch that contains instance(s) of the trigger filters
      return generateNotificationMessageForInstanceWithRefsUpdate(context, user, data, listenedInstancesInPatchIds);
    }
    // the modification may be a modification of rights (the instance is newly/no-more visible) -> we go in case 3.
  }
  // -- 03. --> Newly/no more visible instance containing listened refs
  // It's the data refs that contain instance(s) of the trigger filters (translatedType = create/delete)
  // we don't want updates that doesn't involve a modification of rights (ex: modification of the description of an entity that has listened instances in its refs)
  if (translatedType !== EVENT_TYPE_UPDATE) {
    // fetch the instance data refs
    // -case instance no more visible : fetch data refs before the modifications -> data refs of 'previousData'
    // -else (ie newly visible instance / creation / deletion): fetch data refs after the modification / at creation / at deletion -> data refs of 'data'
    const dataRefs = (translatedType === EVENT_TYPE_DELETE && previousData) ? stixRefsExtractor(previousData) : stixRefsExtractor(data);
    // We need to filter these instances to keep those that are part of the event refs or of the relationship from/to
    const listenedInstancesInRefsEventIds = filterInstancesByRefEventIds(listenedInstanceIdsMap, dataRefs);
    if (listenedInstancesInRefsEventIds.length > 0) {
      return generateNotificationMessageForInstanceWithRefs(context, user, data, listenedInstancesInRefsEventIds);
    }
  }
  return undefined; // filtered event (ex: update of an instance containing a listened ref) : no notification
};

export interface UpdateEventContext {
  readonly previous: Readonly<StixCoreObject | StixRelationshipObject>;
  readonly eventContext: Readonly<FilterEventContext>;
}

// Derived from the stream event only: identical for every trigger of the same event.
// eventContext drives has_changed/not_has_changed filter evaluation.
export const buildUpdateEventContext = (streamEvent: SseEvent<DataEvent>): UpdateEventContext => {
  const { data: { data } } = streamEvent;
  const { context: updatePatch } = streamEvent.data as UpdateEvent;
  const { newDocument: previous } = jsonpatch.applyPatch(structuredClone(data), updatePatch.reverse_patch);
  return { previous, eventContext: buildFilterEventContext(streamEvent.data as UpdateEvent) };
};

export const buildTargetEvents = async (
  context: AuthContext,
  users: AuthUser[],
  streamEvent: SseEvent<DataEvent>,
  trigger: BasicStoreEntityLiveTrigger,
  useSideEventMatching = false,
  getUpdateEventContext: () => UpdateEventContext,
) => {
  const { data: { data }, event: eventType } = streamEvent;
  const { event_types, notifiers, instance_trigger, filters, raw_filters } = trigger;
  let finalFilters = raw_filters;
  if (filters) {
    finalFilters = JSON.parse(filters);
  }
  if (useSideEventMatching) { // modify filters to look for instance trigger side events
    const sideFilters = raw_filters ?? JSON.parse(trigger.filters);
    finalFilters = replaceFilterKey(sideFilters, CONNECTED_TO_INSTANCE_FILTER, CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER);
  }
  let triggerEventTypes = event_types;
  if (instance_trigger && event_types.includes(EVENT_TYPE_UPDATE)) {
    triggerEventTypes = useSideEventMatching
      ? [EVENT_TYPE_UPDATE, EVENT_TYPE_CREATE, EVENT_TYPE_DELETE] // extends trigger event types for side events search
      : [...event_types, EVENT_TYPE_CREATE]; // create is always included for instance_triggers with update in their event_types
  }
  const targets: Array<{ user: NotificationUser; type: string; message: string }> = [];
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  if (eventType === EVENT_TYPE_UPDATE) {
    const { context: updatePatch } = streamEvent.data as UpdateEvent;
    const { previous, eventContext } = getUpdateEventContext();
    for (let indexUser = 0; indexUser < users.length; indexUser += 1) {
      // For each user for a specific trigger
      const user = users[indexUser];
      const user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
      const userContext = { ...context, user_inside_platform_organization };
      const notificationUser = convertToNotificationUser(user, notifiers);
      // TODO: replace with new matcher, but handle side events
      // Check if the user has access to the stream event (stream event data related_restrictions)
      const userHasAccessToUpdateEvent = await isUserCanAccessStreamUpdateEvent(user, streamEvent.data);
      if (userHasAccessToUpdateEvent) {
        // Check if the event matched/matches the trigger filters and the user rights
        const isPreviousMatch = await isStixMatchFilterGroup(userContext, user, previous, finalFilters, eventContext);
        const isCurrentlyMatch = await isStixMatchFilterGroup(userContext, user, data, finalFilters, eventContext);
        // Depending on the previous visibility, the displayed event type will be different
        if (!useSideEventMatching) { // Case classic live trigger & instance trigger direct events: user should be notified of the direct event
          const translatedType = eventTypeTranslater(isPreviousMatch, isCurrentlyMatch, eventType);
          // Case 01. No longer visible because of a data update (user loss of rights OR instance_trigger & remove a listened instance in the refs)
          if (isPreviousMatch && !isCurrentlyMatch && triggerEventTypes.includes(translatedType)) { // translatedType = delete
            const message = await generateNotificationMessageForInstance(userContext, user, data);
            targets.push({ user: notificationUser, type: translatedType, message });
          } else
            // Case 02. Newly visible because of a data update (gain of rights OR instance_trigger & add a listened instance in the refs)
            if (!isPreviousMatch && isCurrentlyMatch && triggerEventTypes.includes(translatedType)) { // translated type = create
              const message = await generateNotificationMessageForInstance(userContext, user, data);
              targets.push({ user: notificationUser, type: translatedType, message });
            } else if (isCurrentlyMatch && triggerEventTypes.includes(translatedType)) {
            // Case 03. Just an update
              const message = await generateNotificationMessageForInstance(userContext, user, data);
              targets.push({ user: notificationUser, type: translatedType, message });
            }
        } else { // useSideEventMatching = true: Case side events for instance triggers
          if (isPreviousMatch || isCurrentlyMatch) { // we keep events if : was visible and/or is visible
            const listenedInstanceIdsMap = await resolveFiltersMapForUser(userContext, user, finalFilters);
            // eslint-disable-next-line max-len
            const translatedType = await eventTypeTranslaterForSideEvents(userContext, user, isPreviousMatch, isCurrentlyMatch, eventType, previous, data, listenedInstanceIdsMap, updatePatch);
            const message = await generateNotificationMessageForFilteredSideEvents(userContext, user, data, finalFilters, translatedType, updatePatch, previous);
            if (message) {
              targets.push({ user: notificationUser, type: translatedType, message });
            }
          }
        }
      }
    }
  } else if (triggerEventTypes.includes(eventType)) { // create or delete
    for (let indexUser = 0; indexUser < users.length; indexUser += 1) {
      const user = users[indexUser];
      const user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
      const userContext = { ...context, user_inside_platform_organization };
      const notificationUser = convertToNotificationUser(user, notifiers);
      // For creation events, pass isCreation context so has_changed evaluates to true when field is non-null
      // For delete events, no eventContext: has_changed evaluates to false, not_has_changed to true
      const eventContext = eventType === EVENT_TYPE_CREATE ? { changedAttributes: [], isCreation: true } : undefined;
      const isCurrentlyMatch = await isStixMatchFilterGroup(userContext, user, data, finalFilters, eventContext);
      if (isCurrentlyMatch) {
        if (!useSideEventMatching) { // classic live trigger or instance trigger with direct event
          const message = await generateNotificationMessageForInstance(userContext, user, data);
          targets.push({ user: notificationUser, type: eventType, message });
        } else { // instance trigger side events
          const message = await generateNotificationMessageForFilteredSideEvents(userContext, user, data, finalFilters, eventType);
          if (message) {
            targets.push({ user: notificationUser, type: eventType, message });
          }
        }
      }
    }
  }
  if (targets.length) {
    // Remove webhook duplicates: Ensure that 1 notification results in only 1 webhook call, regardless of the number of users in the group.
    const allNotifiers = await getEntitiesListFromCache<BasicStoreEntityNotifier>(context, SYSTEM_USER, ENTITY_TYPE_NOTIFIER);
    const webhookNotifiers = allNotifiers.filter((notifier) => notifier.notifier_connector_id === NOTIFIER_CONNECTOR_WEBHOOK)
      .map((notifier) => notifier.id);
    const targetedWebhooks = new Set();

    for (let i = 0; i < targets.length; i += 1) {
      const target = targets[i];
      target.user.notifiers = target.user.notifiers.filter((notifiersId) => {
        if (webhookNotifiers.includes(notifiersId)) {
          if (targetedWebhooks.has(notifiersId)) return false;
          targetedWebhooks.add(notifiersId);
        }
        return true;
      });
    }
  }
  return targets;
};

const notificationLiveStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>) => {
  try {
    if (streamEvents.length === 0) {
      return;
    }
    const context = executionContext(NOTIFICATION_MANAGER_NAME);
    const liveNotifications = await getLiveNotifications(context);
    const version = EVENT_NOTIFICATION_VERSION;
    for (let index = 0; index < streamEvents.length; index += 1) {
      const streamEvent = streamEvents[index];
      const { data: { data, message: streamMessage, origin } } = streamEvent;
      const getUpdateEventContext = memoize(() => buildUpdateEventContext(streamEvent));
      // For each event we need to check ifs
      for (let notifIndex = 0; notifIndex < liveNotifications.length; notifIndex += 1) {
        const { users, trigger }: ResolvedLive = liveNotifications[notifIndex];
        const { internal_id: notification_id, trigger_type: type, instance_trigger } = trigger;
        const targets = await buildTargetEvents(context, users, streamEvent, trigger, false, getUpdateEventContext);
        if (targets.length > 0) {
          const notificationEvent: KnowledgeNotificationEvent = { version, notification_id, type, targets, data, streamMessage, origin };
          await storeNotificationEvent(context, notificationEvent);
        }
        // search side events for instance_trigger
        if (instance_trigger && trigger.event_types.includes(EVENT_TYPE_UPDATE)) {
          const sideTargets = await buildTargetEvents(context, users, streamEvent, trigger, true, getUpdateEventContext);
          if (sideTargets.length > 0) {
            const notificationEvent: KnowledgeNotificationEvent = { version, notification_id, type, targets: sideTargets, data, streamMessage, origin };
            await storeNotificationEvent(context, notificationEvent);
          }
        }
      }
      await redisSetManagerEventState(NOTIFICATION_MANAGER_NAME, streamEvent.id);
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] Notification manager error', { cause: e, manager: 'NOTIFICATION_MANAGER' });
  }
};

interface DigestContentAccumulator { content: Array<KnowledgeNotificationEvent>; byteSize: number; truncated: boolean }
// Accumulate the digest-matching events of a notification batch into `acc`, bounded by the byte budget.
// Returns false to stop the range iteration once the cumulative byte budget is reached.
const collectDigestBatch = (
  acc: DigestContentAccumulator,
  events: Array<SizedNotifEvent<KnowledgeNotificationEvent>>,
  triggerIds: Set<string>,
  maxContentByteSize: number,
): boolean => {
  for (let i = 0; i < events.length; i += 1) {
    const { event: notification, byteSize: notificationSize } = events[i];
    if (triggerIds.has(notification.notification_id)) {
      acc.content.push(notification);
      acc.byteSize += notificationSize;
      if (acc.byteSize >= maxContentByteSize) {
        acc.truncated = true;
        return false; // memory threshold reached, stop reading the range
      }
    }
  }
  return true;
};

// Read the notification events of the [fromDate, toDate] range that belong to the given digest triggers.
// The range is consumed in batches and "only" the matching events are kept in memory (instead of loading the
// whole range). The retained content is bounded by its cumulative byte size (events may vary a lot in size) to
// protect against out-of-memory on huge ranges.
export const collectDigestContent = async (
  fromDate: Date,
  toDate: Date,
  triggerIds: Array<string>,
  maxContentByteSize: number = MAX_DIGEST_CONTENT_SIZE,
): Promise<DigestContentAccumulator> => {
  const acc: DigestContentAccumulator = { content: [], byteSize: 0, truncated: false };
  const triggerIdsSet = new Set(triggerIds);
  await fetchRangeNotifications<KnowledgeNotificationEvent>(
    fromDate,
    toDate,
    (events) => collectDigestBatch(acc, events, triggerIdsSet, maxContentByteSize),
  );
  return acc;
};

export const handleDigestNotifications = async (context: AuthContext) => {
  const baseDate = utcDate().startOf('minutes');
  // Get digest that need to be executed
  const digestNotifications = await getDigestNotifications(context, baseDate);
  // Iter on each digest and generate the output
  for (let index = 0; index < digestNotifications.length; index += 1) {
    const { trigger, users } = digestNotifications[index];
    const { period, trigger_ids: triggerIds, notifiers, internal_id: notification_id, trigger_type: type } = trigger;
    const fromDate = baseDate.clone().subtract(1, period).toDate();
    // Read the range in batches and only keep the events related to this digest (bounded by MAX_DIGEST_CONTENT_SIZE)
    const { content: digestContent, truncated, byteSize } = await collectDigestContent(fromDate, baseDate.toDate(), triggerIds);
    if (truncated) {
      logApp.warn('[OPENCTI-MODULE] Digest content truncated, memory budget reached', { notification_id, period, kept: digestContent.length, byteSize, maxByteSize: MAX_DIGEST_CONTENT_SIZE });
    }
    if (digestContent.length > 0) {
      // Range of results must filtered to keep only data related to the digest
      // And related to the users participating to the digest
      for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
        const user = users[userIndex];
        const userNotifications = digestContent.filter((d) => d.targets
          .map((t) => t.user.user_id).includes(user.internal_id));
        if (userNotifications.length > 0) {
          const version = EVENT_NOTIFICATION_VERSION;
          const target = convertToNotificationUser(user, notifiers);
          const dataPromises = userNotifications.map(async (n) => {
            const userTarget = n.targets.find((t) => t.user.user_id === user.internal_id);
            return ({
              notification_id: n.notification_id,
              type: userTarget?.type ?? type,
              instance: n.data,
              message: await generateNotificationMessageForInstance(context, user, n.data),
              origin: n.origin,
              streamMessage: n.streamMessage,
            });
          });
          const data = await Promise.all(dataPromises);
          const digestEvent: DigestEvent = { version, notification_id, type, target, data };
          await storeNotificationEvent(context, digestEvent);
        }
      }
    }
  }
};

export const isChangeDigest = (n: ResolvedTrigger): n is ResolvedDigest => {
  return n.trigger.trigger_type === TRIGGER_TYPE_CHANGE_DIGEST;
};

const CHANGE_DIGEST_CONCURRENCY = 2;
// Jobs handed to the queue at each pass of the digest loop; the next ones wait in the schedule for a later pass
const CHANGE_DIGEST_BATCH_SIZE = 100;
// A change digest still waiting a week after the end of its period is not sent any more
export const CHANGE_DIGEST_MAX_DELAY_MS = 7 * 24 * 60 * 60 * 1000;
// A digest that cannot be built or stored is tried again 5, 10, 20 and 40 minutes later; a job makes five attempts at
// most, failed or stored, then is dropped
export const CHANGE_DIGEST_MAX_ATTEMPTS = 5;
export const CHANGE_DIGEST_RETRY_DELAY_MS = 5 * 60 * 1000;
// A stored digest is checked again once its delivery claims lapsed: a delivery stopped midway can be sent again by then
export const CHANGE_DIGEST_DELIVERY_CHECK_MS = DIGEST_DELIVERY_CLAIM_MS + CHANGE_DIGEST_RETRY_DELAY_MS;
const CHANGE_DIGEST_JOB_SEPARATOR = '|';
export const CHANGE_DIGEST_JOB_LOCK_PREFIX = 'change_digest_job_lock_';
// A change digest computes a landscape diff per recipient: the computations run apart from the scheduler loop, a few at
// a time, so a long one never makes another digest miss its scheduled minute. Each job stays in the Redis schedule
// until its digest is delivered: a full queue, a restart or a crash delays a digest, the next pass or lock holder
// picks it up. A due minute that no pass ran is scheduled by the next one (planChangeDigests).
export const changeDigestQueue = createBoundedJobQueue('Change digest', CHANGE_DIGEST_CONCURRENCY, CHANGE_DIGEST_BATCH_SIZE);

interface ChangeDigestJob {
  triggerId: string;
  userId: string;
  fromDate: string;
  toDate: string;
}

export const toChangeDigestJobMember = (job: ChangeDigestJob) => {
  return [job.triggerId, job.userId, job.fromDate, job.toDate].join(CHANGE_DIGEST_JOB_SEPARATOR);
};

const parseChangeDigestJobMember = (member: string): ChangeDigestJob | undefined => {
  const parts = member.split(CHANGE_DIGEST_JOB_SEPARATOR);
  if (parts.length !== 4 || parts.some((part) => part.length === 0)) {
    return undefined;
  }
  const [triggerId, userId, fromDate, toDate] = parts;
  return { triggerId, userId, fromDate, toDate };
};

const removeChangeDigestJob = async (member: string) => {
  try {
    await redisRemoveChangeDigestJob(member);
    return true;
  } catch (err) {
    // The job stays scheduled and runs again at a later pass
    logApp.error('[OPENCTI-MODULE] Change digest job could not be removed from the schedule', { cause: err, manager: 'NOTIFICATION_MANAGER' });
    return false;
  }
};

interface ChangeDigestTask {
  context: AuthContext;
  settings: BasicStoreSettings;
  digest: ResolvedDigest;
  user: AuthUser;
  job: ChangeDigestJob;
  member: string;
  dueAt: number;
}

// Returns false when nothing changed over the period. Throws when the digest cannot be built or stored, or when the job
// lock is lost before it is stored
const sendChangeDigest = async (task: ChangeDigestTask, lockSignal: AbortSignal) => {
  const { context, settings, digest: { trigger }, user, job, member } = task;
  const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
  const locale = resolveChangeDigestLocale(user.language, settings.platform_language);
  const data = await buildChangeDigestData(userContext, user, trigger as unknown as ChangeDigestTrigger, job.fromDate, job.toDate, locale);
  if (data.length === 0) {
    return false;
  }
  lockSignal.throwIfAborted();
  const target = convertToNotificationUser(user, trigger.notifiers);
  // Stored again by a later attempt until every notifier received it: the publisher delivers it once per notifier
  const digestEvent: DigestEvent = { version: EVENT_NOTIFICATION_VERSION, notification_id: trigger.internal_id, type: 'digest', target, data, delivery_key: member };
  await storeNotificationEvent(context, digestEvent);
  return true;
};

const changeDigestDelivery = async ({ digest: { trigger }, member }: ChangeDigestTask) => {
  const receipts = (trigger.notifiers ?? []).map((notifierId) => toDigestDeliveryReceipt(member, notifierId));
  if (receipts.length === 0) {
    return 'no_notifier';
  }
  return (await redisAreDigestDeliveriesConfirmed(receipts)) ? 'delivered' : 'pending';
};

// A stored digest stays scheduled until every notifier received it: checked again later, after the last attempt too
const checkChangeDigestDeliveryLater = async (member: string, triggerId: string) => {
  try {
    await redisCountChangeDigestJobAttempt(member);
    await redisRescheduleChangeDigestJob(member, utcDate().valueOf() + CHANGE_DIGEST_DELIVERY_CHECK_MS);
  } catch (err) {
    // The job keeps its place: the next pass finds the digest delivered or stores it again for the notifiers without a receipt
    logApp.error('[OPENCTI-MODULE] Change digest stored, its delivery check could not be scheduled', { cause: err, manager: 'NOTIFICATION_MANAGER', trigger_id: triggerId });
  }
};

// A failed digest stays scheduled for a later attempt, until the last one
const retryChangeDigestJob = async (member: string, triggerId: string, cause: unknown) => {
  try {
    const attempts = await redisCountChangeDigestJobAttempt(member);
    if (attempts >= CHANGE_DIGEST_MAX_ATTEMPTS) {
      logApp.error('[OPENCTI-MODULE] Change digest not sent, every attempt failed', { cause, manager: 'NOTIFICATION_MANAGER', trigger_id: triggerId, attempts });
      await removeChangeDigestJob(member);
      return;
    }
    const retryAt = utcDate().valueOf() + CHANGE_DIGEST_RETRY_DELAY_MS * 2 ** (attempts - 1);
    logApp.warn('[OPENCTI-MODULE] Change digest generation error, tried again later', { cause, manager: 'NOTIFICATION_MANAGER', trigger_id: triggerId, attempts, retry_at: new Date(retryAt).toISOString() });
    await redisRescheduleChangeDigestJob(member, retryAt);
  } catch (err) {
    // The job keeps its place and runs again at the next pass
    logApp.error('[OPENCTI-MODULE] Change digest generation error, the attempt could not be recorded', { cause: err, manager: 'NOTIFICATION_MANAGER', trigger_id: triggerId });
  }
};

// One platform at a time owns a job: the lock is extended while the digest is computed and expires if its holder stops,
// so a lock handover of the notification manager never sends the same digest twice
const runChangeDigestJob = async (task: ChangeDigestTask) => {
  const { member, dueAt, digest } = task;
  let jobLock;
  try {
    jobLock = await lockResources([`${CHANGE_DIGEST_JOB_LOCK_PREFIX}${member}`], { retryCount: 0 });
  } catch (err) {
    // Held by another platform, which sends or reschedules the digest; otherwise tried again at a later pass
    logApp.debug('[OPENCTI-MODULE] Change digest job not owned', { cause: err, manager: 'NOTIFICATION_MANAGER', trigger_id: digest.trigger.internal_id });
    return;
  }
  try {
    // Sent by a previous owner, or moved to a later attempt
    if (!(await redisIsChangeDigestJobDue(member, dueAt))) {
      return;
    }
    const delivery = await changeDigestDelivery(task);
    if (delivery === 'delivered') {
      // Stored by an earlier attempt and received through every notifier: counted once, as its job leaves the schedule
      if (await removeChangeDigestJob(member)) {
        addChangeDigestSentCount();
      }
      return;
    }
    if (delivery === 'no_notifier') {
      await removeChangeDigestJob(member);
      return;
    }
    // A failed last attempt removes the job: one still scheduled here was stored by its last attempt
    const attempts = await redisGetChangeDigestJobAttempts(member);
    if (attempts >= CHANGE_DIGEST_MAX_ATTEMPTS) {
      logApp.error('[OPENCTI-MODULE] Change digest not received through every notifier, every attempt made', { manager: 'NOTIFICATION_MANAGER', trigger_id: digest.trigger.internal_id, attempts });
      await removeChangeDigestJob(member);
      return;
    }
    let stored: boolean;
    try {
      stored = await sendChangeDigest(task, jobLock.signal);
    } catch (err) {
      if (jobLock.signal.aborted) {
        // Another platform may own the job now: it decides
        return;
      }
      await retryChangeDigestJob(member, digest.trigger.internal_id, err);
      return;
    }
    if (stored) {
      await checkChangeDigestDeliveryLater(member, digest.trigger.internal_id);
    } else {
      await removeChangeDigestJob(member);
    }
  } finally {
    try {
      await jobLock.unlock();
    } catch (err) {
      logApp.warn('[OPENCTI-MODULE] Change digest job lock could not be released', { cause: err, manager: 'NOTIFICATION_MANAGER' });
    }
  }
};

export interface ChangeDigestPlan {
  jobs: Array<{ score: number; member: string }>;
  // Trigger id -> end of the period now scheduled
  watermarks: Array<[string, string]>;
}

/**
 * One job per recipient for each change digest whose last due minute is newer than the end of its last scheduled
 * period (its watermark): the minute of baseDate, or one missed while no notification manager ran it. The period starts
 * at the watermark, so missed periods are sent together, at most CHANGE_DIGEST_MAX_DELAY_MS before the usual period;
 * without a watermark it is the usual period. A trigger first seen after its due minute, or a minute missed longer ago
 * than CHANGE_DIGEST_MAX_DELAY_MS (its job would expire unsent), only moves the watermark.
 */
export const planChangeDigests = (changeDigests: Array<ResolvedDigest>, watermarks: Map<string, string>, baseDate: Moment): ChangeDigestPlan => {
  const now = baseDate.clone().startOf('minutes');
  const plan: ChangeDigestPlan = { jobs: [], watermarks: [] };
  changeDigests.forEach((digest) => {
    const { trigger, users } = digest;
    const dueDate = lastDigestDueDate(digest, now);
    const watermark = watermarks.get(trigger.internal_id);
    if (!dueDate || (watermark && !dueDate.isAfter(utcDate(watermark)))) {
      return;
    }
    const toDate = dueDate.toISOString();
    plan.watermarks.push([trigger.internal_id, toDate]);
    const missed = !dueDate.isSame(now);
    if ((missed && !watermark) || now.diff(dueDate) > CHANGE_DIGEST_MAX_DELAY_MS) {
      return;
    }
    const periodStart = dueDate.clone().subtract(1, trigger.period);
    const oldestStart = periodStart.clone().subtract(CHANGE_DIGEST_MAX_DELAY_MS, 'milliseconds');
    let from = periodStart;
    if (watermark) {
      const watermarkDate = utcDate(watermark);
      from = watermarkDate.isBefore(oldestStart) ? oldestStart : watermarkDate;
    }
    const fromDate = from.toISOString();
    users.forEach((user) => {
      const member = toChangeDigestJobMember({ triggerId: trigger.internal_id, userId: user.internal_id, fromDate, toDate });
      plan.jobs.push({ score: dueDate.valueOf(), member });
    });
  });
  return plan;
};

// Hands the oldest scheduled change digests to the queue; a job leaves the schedule once its digest is delivered
const runChangeDigestJobs = async (context: AuthContext, notifications: Array<ResolvedTrigger>, baseDate: Moment) => {
  const expired = await redisExpireChangeDigestJobs(baseDate.valueOf() - CHANGE_DIGEST_MAX_DELAY_MS);
  if (expired > 0) {
    logApp.warn('[OPENCTI-MODULE] Change digests not sent, their period ended more than a week ago', { manager: 'NOTIFICATION_MANAGER', count: expired });
  }
  const members = await redisGetChangeDigestJobs(baseDate.valueOf(), CHANGE_DIGEST_BATCH_SIZE);
  if (members.length === 0) {
    return;
  }
  const changeDigests = new Map(notifications.filter(isChangeDigest).map((digest) => [digest.trigger.internal_id, digest]));
  const recipients = new Map<string, Map<string, AuthUser>>();
  const findRecipient = (digest: ResolvedDigest, userId: string) => {
    if (!recipients.has(digest.trigger.internal_id)) {
      recipients.set(digest.trigger.internal_id, new Map(digest.users.map((user) => [user.internal_id, user])));
    }
    return recipients.get(digest.trigger.internal_id)?.get(userId);
  };
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    const job = parseChangeDigestJobMember(member);
    const digest = job ? changeDigests.get(job.triggerId) : undefined;
    const user = job && digest ? findRecipient(digest, job.userId) : undefined;
    if (!job || !digest || !user || user.user_service_account) {
      // The trigger is deleted or no longer a change digest, or the user is no longer one of its recipients or is a
      // service account, which receives no notification
      await removeChangeDigestJob(member);
    } else {
      const task: ChangeDigestTask = { context, settings, digest, user, job, member, dueAt: baseDate.valueOf() };
      changeDigestQueue.enqueue(member, () => runChangeDigestJob(task));
    }
  }
};

// Change digests send, for each recipient, the landscape diff of the trigger filter set over the digest period
export const handleChangeDigestNotifications = async (context: AuthContext) => {
  const baseDate = utcDate().startOf('minutes');
  const notifications = await getNotifications(context);
  const changeDigests = notifications.filter(isChangeDigest);
  const watermarks = await redisGetChangeDigestWatermarks(changeDigests.map(({ trigger }) => trigger.internal_id));
  const plan = planChangeDigests(changeDigests, watermarks, baseDate);
  // The jobs first: a watermark is only moved once its period is scheduled
  await redisAddChangeDigestJobs(plan.jobs);
  await redisSetChangeDigestWatermarks(plan.watermarks);
  await runChangeDigestJobs(context, notifications, baseDate);
};

const initNotificationManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let streamScheduler: SetIntervalAsyncTimer<[]>;
  let cronScheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let running = false;
  let shutdown = false;
  const liveTimer = new InterruptibleTimer();
  const cronTimer = new InterruptibleTimer();

  const notificationLiveHandler = async () => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResources([NOTIFICATION_LIVE_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-MODULE] Running notification manager (live)');
      streamProcessor = createStreamProcessor('Notification manager', notificationLiveStreamHandler);
      const lastEventState = await redisGetManagerEventState(NOTIFICATION_MANAGER_NAME);
      await streamProcessor.start(lastEventState ?? 'live');
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        await liveTimer.start(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of notification manager processing (live)');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Notification manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Notification manager live handler error', { cause: e, manager: 'NOTIFICATION_MANAGER' });
      }
    } finally {
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };

  const notificationDigestHandler = async () => {
    const context = executionContext(NOTIFICATION_MANAGER_NAME);
    let lock;
    try {
      // Lock the manager
      lock = await lockResources([NOTIFICATION_DIGEST_KEY], { retryCount: 0 });
      logApp.info('[OPENCTI-MODULE] Running notification manager (digest)');
      while (!shutdown) {
        lock.signal.throwIfAborted();
        await handleDigestNotifications(context);
        await handleChangeDigestNotifications(context);
        await cronTimer.start(CRON_SCHEDULE_TIME);
      }
      logApp.info('[OPENCTI-MODULE] End of notification manager processing (digest)');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Notification manager (digest) already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Notification manager digest handler error', { cause: e, manager: 'NOTIFICATION_MANAGER' });
      }
    } finally {
      if (lock) {
        // The change digests not started stay scheduled for the next lock holder
        changeDigestQueue.clear();
        await lock.unlock();
      }
    }
  };
  return {
    start: async () => {
      streamScheduler = setIntervalAsync(async () => {
        await notificationLiveHandler();
      }, STREAM_SCHEDULE_TIME);
      cronScheduler = setIntervalAsync(async () => {
        await notificationDigestHandler();
      }, CRON_SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'NOTIFICATION_MANAGER',
        enable: booleanConf('notification_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      const startTime = Date.now();
      logApp.info('[OPENCTI-MODULE] Stopping notification manager');
      shutdown = true;
      liveTimer.interrupt();
      cronTimer.interrupt();
      if (streamScheduler) await clearIntervalAsync(streamScheduler);
      if (cronScheduler) await clearIntervalAsync(cronScheduler);
      logApp.info(`[OPENCTI-MODULE] Notification manager stopped in ${new Date().getTime() - startTime} ms`);
      return true;
    },
  };
};
const notificationManager = initNotificationManager();

export default notificationManager;
