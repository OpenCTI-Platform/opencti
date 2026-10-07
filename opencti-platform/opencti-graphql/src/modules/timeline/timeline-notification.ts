import type { AuthContext, AuthUser, UserOrigin } from '../../types/user';
import type { BasicStoreCommon } from '../../types/store';
import { isUserCanAccessStixElement, isUserCanAccessStoreElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { stixLoadById } from '../../database/middleware';
import { internalFindByIds } from '../../database/middleware-loader';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import {
  convertToNotificationUser,
  EVENT_NOTIFICATION_VERSION,
  getLiveNotifications,
  type KnowledgeNotificationEvent,
  removeWebhookDuplicates,
} from '../../manager/notificationManager';
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

interface TimelineNotificationMessage {
  message: string;
  describedEvent?: BasicStoreCommon;
}

const describedElementIdOf = (event: BasicStoreCommon | undefined, containerId: string): string | null => {
  const elementId = event && (event as BasicStoreCommon & { element_id?: string | null }).element_id;
  return elementId && elementId !== containerId ? elementId : null;
};

/**
 * Deliver timeline notifications to the live triggers listening to the given event type.
 * Every recipient must be able to access the container and match the trigger filters, exactly as
 * for knowledge events; digests built on these triggers collect them like any live notification.
 * When a message describes a timeline event, the recipient must also be able to access that event.
 * The triggers, the container, the elements and the filter match of each recipient are read once
 * for all the messages: a bulk import never evaluates them once per milestone.
 */
const notifyTimelineTrigger = async (
  context: AuthContext,
  containerId: string,
  eventType: TriggerEventType,
  buildMessages: (stix: StixObject) => TimelineNotificationMessage[],
  origin: Partial<UserOrigin>,
) => {
  const liveNotifications = await getLiveNotifications(context);
  const candidates = liveNotifications.filter(({ trigger }) => (trigger.event_types ?? []).includes(eventType));
  if (candidates.length === 0) return 0;
  const stix = await stixLoadById(context, SYSTEM_USER, containerId) as StixObject | undefined;
  if (!stix) return 0;
  const messages = buildMessages(stix);
  // Like the timeline reads, an event about an element is only visible to the users who can access that element
  const elementIds = Array.from(new Set(messages.map(({ describedEvent }) => describedElementIdOf(describedEvent, containerId))
    .filter((id): id is string => !!id)));
  const elements = elementIds.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, elementIds, { toMap: true }) as unknown as Record<string, BasicStoreCommon>
    : {};
  const deliverable = messages.filter(({ describedEvent }) => {
    const elementId = describedElementIdOf(describedEvent, containerId);
    return !elementId || !!elements[elementId];
  });
  if (deliverable.length === 0) return 0;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  let delivered = 0;
  for (let index = 0; index < candidates.length; index += 1) {
    const { users, trigger } = candidates[index];
    const filters = trigger.filters ? JSON.parse(trigger.filters) : trigger.raw_filters;
    const recipients: { user: AuthUser; userContext: AuthContext }[] = [];
    for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
      const user: AuthUser = users[userIndex];
      const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
      if (await isUserCanAccessStixElement(userContext, user, stix) && await isStixMatchFilterGroup(userContext, user, stix, filters)) {
        recipients.push({ user, userContext });
      }
    }
    for (let messageIndex = 0; recipients.length > 0 && messageIndex < deliverable.length; messageIndex += 1) {
      const { message, describedEvent } = deliverable[messageIndex];
      const elementId = describedElementIdOf(describedEvent, containerId);
      const describedElement = elementId ? elements[elementId] : null;
      const targets: KnowledgeNotificationEvent['targets'] = [];
      for (let recipientIndex = 0; recipientIndex < recipients.length; recipientIndex += 1) {
        const { user, userContext } = recipients[recipientIndex];
        const canAccess = (!describedEvent || await isUserCanAccessStoreElement(userContext, user, describedEvent))
          && (!describedElement || await isUserCanAccessStoreElement(userContext, user, describedElement));
        if (canAccess) targets.push({ user: convertToNotificationUser(user, trigger.notifiers), type: eventType, message });
      }
      if (targets.length > 0) {
        await removeWebhookDuplicates(context, targets);
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
    (stix) => [{ message: `[timeline] \`${extractStixRepresentative(stix)}\`: ${changes.join(', ')}` }],
    { user_id: SYSTEM_USER.id },
  );
};

type TimelineMilestone = BasicStoreCommon & { name: string; kind: string; event_time: string };

/** Notify the "Timeline milestone added" trigger for milestones just written by the same author, one message each. */
export const notifyTimelineMilestonesAdded = async (context: AuthContext, user: AuthUser, containerId: string, milestones: TimelineMilestone[]) => {
  if (milestones.length === 0) return 0;
  return notifyTimelineTrigger(
    context,
    containerId,
    TIMELINE_TRIGGER_MILESTONE_ADDED,
    (stix) => milestones.map((milestone) => ({
      message: `[timeline] \`${extractStixRepresentative(stix)}\`: ${milestone.kind} \`${milestone.name}\` at ${milestone.event_time}`,
      describedEvent: milestone,
    })),
    { user_id: user.id },
  );
};

export const notifyTimelineMilestoneAdded = async (context: AuthContext, user: AuthUser, containerId: string, milestone: TimelineMilestone) => {
  return notifyTimelineMilestonesAdded(context, user, containerId, [milestone]);
};
