import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreSettings } from '../../types/settings';
import type { StixObject } from '../../types/stix-2-1-common';
import { isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { stixLoadById } from '../../database/middleware';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION, getLiveNotifications, type KnowledgeNotificationEvent } from '../../manager/notificationManager';
import { extractStixRepresentative } from '../../database/stix-representative';
import { TriggerEventType } from '../../generated/graphql';
import { doYield } from '../../utils/eventloop-utils';
import {
  DEFENSE_LEVEL_DETECTION_AVAILABLE,
  DEFENSE_LEVEL_DETECTION_DEPLOYED,
  DEFENSE_LEVEL_NONE,
  DEFENSE_LEVEL_TELEMETRY,
  DEFENSE_LEVEL_VALIDATED,
  type DefenseCoverage,
} from './defenseCoverage-types';

export const DEFENSE_TRIGGER_LEVEL_DECREASED = TriggerEventType.DefenseLevelDecreased;
export const DEFENSE_TRIGGER_LEVEL_INCREASED = TriggerEventType.DefenseLevelIncreased;

const LEVEL_LABELS: Record<number, string> = {
  [DEFENSE_LEVEL_NONE]: 'none',
  [DEFENSE_LEVEL_TELEMETRY]: 'telemetry',
  [DEFENSE_LEVEL_DETECTION_AVAILABLE]: 'detection available',
  [DEFENSE_LEVEL_DETECTION_DEPLOYED]: 'detection deployed',
  [DEFENSE_LEVEL_VALIDATED]: 'validated',
};

export interface DefenseLevelChange {
  attack_pattern_id: string;
  previous_level: number;
  level: number;
}

/**
 * Aggregate level changes between the stored and the new coverage of techniques.
 * A technique computed for the first time has no previous level: the first computation of a platform
 * is not a change and never notifies.
 */
export const collectDefenseLevelChanges = (
  updates: Array<{ attackPatternId: string; previous: DefenseCoverage | undefined; coverage: DefenseCoverage }>,
): DefenseLevelChange[] => {
  return updates
    .filter(({ previous, coverage }) => !!previous?.computed_at && previous.level !== coverage.level)
    .map(({ attackPatternId, previous, coverage }) => ({
      attack_pattern_id: attackPatternId,
      previous_level: previous?.level ?? DEFENSE_LEVEL_NONE,
      level: coverage.level,
    }));
};

export const defenseLevelEventType = (change: DefenseLevelChange) => {
  return change.level < change.previous_level ? DEFENSE_TRIGGER_LEVEL_DECREASED : DEFENSE_TRIGGER_LEVEL_INCREASED;
};

const levelLabel = (level: number) => `${level} (${LEVEL_LABELS[level] ?? 'unknown'})`;

export const buildDefenseLevelMessage = (stix: StixObject, change: DefenseLevelChange) => {
  const direction = change.level < change.previous_level ? 'decreased' : 'increased';
  return `[defense] \`${extractStixRepresentative(stix)}\`: defense level ${direction} from ${levelLabel(change.previous_level)} to ${levelLabel(change.level)}`;
};

/**
 * Deliver the defense level changes of a computation to the live triggers listening to
 * "Defense level decreased" or "Defense level increased". Every recipient must be able to access the
 * technique and match the trigger filters, exactly as for knowledge events; digests built on these
 * triggers collect them like any live notification. The aggregate level is the stored `defense_level`
 * of the technique, which every reader of the technique already sees.
 * Returns the number of notified recipients.
 */
export const notifyDefenseLevelChanges = async (context: AuthContext, changes: DefenseLevelChange[]) => {
  if (changes.length === 0) return 0;
  const liveNotifications = await getLiveNotifications(context);
  const listening = liveNotifications.filter(({ trigger }) => {
    const eventTypes = trigger.event_types ?? [];
    return eventTypes.includes(DEFENSE_TRIGGER_LEVEL_DECREASED) || eventTypes.includes(DEFENSE_TRIGGER_LEVEL_INCREASED);
  });
  if (listening.length === 0) return 0;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  let delivered = 0;
  for (let changeIndex = 0; changeIndex < changes.length; changeIndex += 1) {
    await doYield();
    const change = changes[changeIndex];
    const eventType = defenseLevelEventType(change);
    const candidates = listening.filter(({ trigger }) => (trigger.event_types ?? []).includes(eventType));
    if (candidates.length > 0) {
      const stix = await stixLoadById(context, SYSTEM_USER, change.attack_pattern_id) as StixObject | undefined;
      if (stix) {
        const message = buildDefenseLevelMessage(stix, change);
        for (let index = 0; index < candidates.length; index += 1) {
          const { users, trigger } = candidates[index];
          const filters = trigger.filters ? JSON.parse(trigger.filters) : trigger.raw_filters;
          const targets: KnowledgeNotificationEvent['targets'] = [];
          for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
            const user: AuthUser = users[userIndex];
            const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
            if (await isUserCanAccessStixElement(userContext, user, stix) && await isStixMatchFilterGroup(userContext, user, stix, filters)) {
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
              origin: { user_id: SYSTEM_USER.id },
            };
            await storeNotificationEvent(context, notificationEvent);
            delivered += targets.length;
          }
        }
      }
    }
  }
  logApp.debug('[DEFENSE-COVERAGE] Defense level changes notified', { changes: changes.length, delivered });
  return delivered;
};
