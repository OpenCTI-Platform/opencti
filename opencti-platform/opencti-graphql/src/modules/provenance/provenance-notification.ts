import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import { storeLoadByIdWithRefs } from '../../database/middleware';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { logApp } from '../../config/conf';
import {
  convertToNotificationUser,
  EVENT_NOTIFICATION_VERSION,
  generateNotificationMessageForInstance,
  getLiveNotifications,
  type KnowledgeNotificationEvent,
} from '../../manager/notificationManager';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext } from '../../types/user';
import type { FilterGroup } from '../../generated/graphql';
import { isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { conflictFieldLabel } from './provenance-conflicts';
import type { StoreProvenanceFields } from './provenance-types';
import {
  type BasicStoreEntityTrigger,
  DEFAULT_CORROBORATION_THRESHOLD,
  ENTITY_TYPE_TRIGGER,
  TRIGGER_EVENT_CONFLICT,
  TRIGGER_EVENT_CORROBORATION,
} from '../notification/notification-types';

export const PROVENANCE_EVENT_CORROBORATION = TRIGGER_EVENT_CORROBORATION;
export const PROVENANCE_EVENT_CONFLICT = TRIGGER_EVENT_CONFLICT;
type ProvenanceEventType = typeof PROVENANCE_EVENT_CORROBORATION | typeof PROVENANCE_EVENT_CONFLICT;

export interface ProvenanceChange {
  // Number of distinct sources before and after the write
  corroboration?: { from: number; to: number };
  // Fields that received a new alternative value from a source
  conflictFields?: string[];
}

/**
 * Live knowledge triggers concerned by a provenance change, with the event types each one listens to.
 * A corroboration trigger fires once, when the number of distinct sources crosses its threshold.
 */
export const computeListeningTriggers = (triggers: BasicStoreEntityTrigger[], change: ProvenanceChange) => {
  const listening = new Map<string, ProvenanceEventType[]>();
  for (let index = 0; index < triggers.length; index += 1) {
    const trigger = triggers[index];
    if (!isProvenanceTrigger(trigger)) {
      continue;
    }
    const eventTypes: ProvenanceEventType[] = [];
    const eventTypesOfTrigger = trigger.event_types ?? [];
    if (change.corroboration && eventTypesOfTrigger.includes(PROVENANCE_EVENT_CORROBORATION)) {
      const threshold = trigger.corroboration_threshold ?? DEFAULT_CORROBORATION_THRESHOLD;
      if (change.corroboration.from < threshold && change.corroboration.to >= threshold) {
        eventTypes.push(PROVENANCE_EVENT_CORROBORATION);
      }
    }
    if ((change.conflictFields ?? []).length > 0 && eventTypesOfTrigger.includes(PROVENANCE_EVENT_CONFLICT)) {
      eventTypes.push(PROVENANCE_EVENT_CONFLICT);
    }
    if (eventTypes.length > 0) {
      listening.set(trigger.internal_id, eventTypes);
    }
  }
  return listening;
};

const isProvenanceTrigger = (trigger: BasicStoreEntityTrigger) => {
  const eventTypes = trigger.event_types ?? [];
  return trigger.trigger_type === 'live' && trigger.trigger_scope === 'knowledge'
    && (eventTypes.includes(PROVENANCE_EVENT_CORROBORATION) || eventTypes.includes(PROVENANCE_EVENT_CONFLICT));
};

/**
 * Cheap guard of the write path (cache only): is any live trigger listening to provenance events.
 */
export const hasProvenanceTriggers = async (context: AuthContext) => {
  const triggers = await getEntitiesListFromCache<BasicStoreEntityTrigger>(context, SYSTEM_USER, ENTITY_TYPE_TRIGGER);
  return triggers.some(isProvenanceTrigger);
};

export const describeProvenanceChange = (eventType: ProvenanceEventType, change: ProvenanceChange, entityType?: string) => {
  if (eventType === PROVENANCE_EVENT_CORROBORATION) {
    return `is now corroborated by ${change.corroboration?.to ?? 0} sources`;
  }
  const fields = (change.conflictFields ?? []).map((field) => conflictFieldLabel(entityType, field));
  return `has conflicting values from sources on ${fields.join(', ')}`;
};

const parseTriggerFilters = (trigger: BasicStoreEntityTrigger): FilterGroup | undefined => {
  if (trigger.filters) {
    return JSON.parse(trigger.filters);
  }
  return trigger.raw_filters ?? undefined;
};

/**
 * Provenance updates never emit stream events (side channel), so the notification events of the
 * provenance trigger types are produced here and consumed like any live trigger event (notifications, digests).
 * `current` is the provenance stored by the write: it replaces the provenance of the loaded element, which a
 * search may still return as it was before the write (no refresh on the write path).
 */
export const notifyProvenanceChange = async (
  context: AuthContext,
  element: { internal_id: string },
  change: ProvenanceChange,
  current: Partial<StoreProvenanceFields> | null = null,
) => {
  try {
    const triggers = await getEntitiesListFromCache<BasicStoreEntityTrigger>(context, SYSTEM_USER, ENTITY_TYPE_TRIGGER);
    const listening = computeListeningTriggers(triggers, change);
    if (listening.size === 0) {
      return 0;
    }
    const liveNotifications = (await getLiveNotifications(context)).filter(({ trigger }) => listening.has(trigger.internal_id));
    if (liveNotifications.length === 0) {
      return 0;
    }
    const loaded = await storeLoadByIdWithRefs(context, SYSTEM_USER, element.internal_id);
    if (!loaded) {
      return 0;
    }
    const instance = current ? { ...loaded, ...current } as typeof loaded : loaded;
    const stix = convertStoreToStix_2_1(instance);
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    let stored = 0;
    for (let notificationIndex = 0; notificationIndex < liveNotifications.length; notificationIndex += 1) {
      const { users, trigger } = liveNotifications[notificationIndex];
      const filters = parseTriggerFilters(trigger);
      const eventTypes = listening.get(trigger.internal_id) ?? [];
      for (let typeIndex = 0; typeIndex < eventTypes.length; typeIndex += 1) {
        const eventType = eventTypes[typeIndex];
        const targets: KnowledgeNotificationEvent['targets'] = [];
        for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
          const user = users[userIndex];
          const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
          // Checks the user access to the element (markings, organizations) and the trigger filters
          const isMatch = await isStixMatchFilterGroup(userContext, user, stix, filters);
          if (isMatch) {
            const message = await generateNotificationMessageForInstance(userContext, user, stix);
            targets.push({ user: convertToNotificationUser(user, trigger.notifiers), type: eventType, message: `${message} ${describeProvenanceChange(eventType, change, instance.entity_type)}` });
          }
        }
        if (targets.length > 0) {
          const notificationEvent: KnowledgeNotificationEvent = {
            version: EVENT_NOTIFICATION_VERSION,
            notification_id: trigger.internal_id,
            type: 'live',
            targets,
            data: stix,
            origin: {},
          };
          await storeNotificationEvent(context, notificationEvent);
          stored += 1;
        }
      }
    }
    return stored;
  } catch (err) {
    logApp.error('[PROVENANCE] Unable to notify the provenance change', { cause: err, id: element.internal_id });
    return 0;
  }
};
