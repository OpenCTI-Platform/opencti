import type { AuthContext, AuthUser, UserOrigin } from '../../types/user';
import { isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { stixLoadById } from '../../database/middleware';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION, getLiveNotifications, type KnowledgeNotificationEvent } from '../../manager/notificationManager';
import type { StixObject } from '../../types/stix-2-1-common';
import { extractStixRepresentative } from '../../database/stix-representative';
import { TriggerEventType } from '../../generated/graphql';
import type { TimelineAnchorKey, TimelineAnchors } from './timeline-types';

export const TIMELINE_TRIGGER_ANCHOR_CHANGED = TriggerEventType.TimelineAnchorChanged;
export const TIMELINE_TRIGGER_MILESTONE_ADDED = TriggerEventType.TimelineMilestoneAdded;

const ANCHOR_LABELS: Record<TimelineAnchorKey, string> = {
  first_adversary_activity: 'first adversary activity',
  first_detection: 'first detection',
  first_response: 'first response',
  containment: 'containment',
  closure: 'closure',
};

/**
 * Deliver a timeline notification to the live triggers listening to the given event type.
 * Every recipient must be able to access the container and match the trigger filters, exactly as
 * for knowledge events; digests built on these triggers collect them like any live notification.
 */
const notifyTimelineTrigger = async (
  context: AuthContext,
  containerId: string,
  eventType: TriggerEventType,
  buildMessage: (stix: StixObject) => string,
  origin: Partial<UserOrigin>,
) => {
  const liveNotifications = await getLiveNotifications(context);
  const candidates = liveNotifications.filter(({ trigger }) => (trigger.event_types ?? []).includes(eventType));
  if (candidates.length === 0) return 0;
  const stix = await stixLoadById(context, SYSTEM_USER, containerId) as StixObject | undefined;
  if (!stix) return 0;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const message = buildMessage(stix);
  let delivered = 0;
  for (let index = 0; index < candidates.length; index += 1) {
    const { users, trigger } = candidates[index];
    const filters = trigger.filters ? JSON.parse(trigger.filters) : trigger.raw_filters;
    const targets: KnowledgeNotificationEvent['targets'] = [];
    for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
      const user: AuthUser = users[userIndex];
      const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
      const canAccess = await isUserCanAccessStixElement(userContext, user, stix);
      if (canAccess && await isStixMatchFilterGroup(userContext, user, stix, filters)) {
        targets.push({ user: convertToNotificationUser(user, trigger.notifiers), type: eventType, message });
      }
    }
    if (targets.length > 0) {
      const notificationEvent: KnowledgeNotificationEvent = {
        version: EVENT_NOTIFICATION_VERSION,
        notification_id: trigger.internal_id,
        type: 'live',
        targets,
        data: stix,
        streamMessage: message,
        origin,
      };
      await storeNotificationEvent(context, notificationEvent);
      delivered += targets.length;
    }
  }
  return delivered;
};

export const notifyTimelineAnchorsChanged = async (
  context: AuthContext,
  containerId: string,
  changedAnchors: TimelineAnchorKey[],
  anchors: TimelineAnchors,
) => {
  const changes = changedAnchors.map((key) => {
    const value = anchors[key];
    return value ? `${ANCHOR_LABELS[key]} set to ${value}` : `${ANCHOR_LABELS[key]} cleared`;
  });
  return notifyTimelineTrigger(
    context,
    containerId,
    TIMELINE_TRIGGER_ANCHOR_CHANGED,
    (stix) => `[timeline] \`${extractStixRepresentative(stix)}\`: ${changes.join(', ')}`,
    { user_id: SYSTEM_USER.id },
  );
};

export const notifyTimelineMilestoneAdded = async (
  context: AuthContext,
  user: AuthUser,
  containerId: string,
  milestone: { name: string; kind: string; event_time: string },
) => {
  return notifyTimelineTrigger(
    context,
    containerId,
    TIMELINE_TRIGGER_MILESTONE_ADDED,
    (stix) => `[timeline] \`${extractStixRepresentative(stix)}\`: ${milestone.kind} \`${milestone.name}\` at ${milestone.event_time}`,
    { user_id: user.id },
  );
};
