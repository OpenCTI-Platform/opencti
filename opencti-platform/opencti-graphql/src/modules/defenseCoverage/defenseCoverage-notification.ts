import * as R from 'ramda';
import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreSettings } from '../../types/settings';
import type { StixObject } from '../../types/stix-2-1-common';
import { isBypassUser, isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
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
import { type AccessPredicate, collectCoverageIds, evaluateCoverage } from './defenseCoverage-utils';
import { findAccessibleIds } from './defenseCoverage-reader';
import { clearPendingLevelChanges, listPendingLevelChanges, replacePendingLevelChanges } from './defenseCoverage-state';

export const DEFENSE_TRIGGER_LEVEL_DECREASED = TriggerEventType.DefenseLevelDecreased;
export const DEFENSE_TRIGGER_LEVEL_INCREASED = TriggerEventType.DefenseLevelIncreased;

const LEVEL_LABELS: Record<number, string> = {
  [DEFENSE_LEVEL_NONE]: 'none',
  [DEFENSE_LEVEL_TELEMETRY]: 'telemetry',
  [DEFENSE_LEVEL_DETECTION_AVAILABLE]: 'detection available',
  [DEFENSE_LEVEL_DETECTION_DEPLOYED]: 'detection deployed',
  [DEFENSE_LEVEL_VALIDATED]: 'validated',
};

// The stored coverage of a technique before and after a computation
export interface DefenseCoverageChange {
  attack_pattern_id: string;
  previous: DefenseCoverage;
  coverage: DefenseCoverage;
  // Triggers already handled for this change by a delivery that failed on a later trigger
  delivered_trigger_ids?: string[];
}

// How far a delivery went: the changes fully handled, and the triggers handled for the next one
export interface DefenseDeliveryProgress {
  done: number;
  triggerIds: string[];
}

// A level change as one recipient sees it
export interface DefenseLevelChange {
  attack_pattern_id: string;
  previous_level: number;
  level: number;
}

/**
 * Coverages that changed since an earlier computation. A technique computed for the first time has no previous
 * coverage: the first computation of a platform is not a change and never notifies. Every other change is kept,
 * even when the aggregate level is the same: what a recipient sees depends on the evidences they can access.
 */
export const collectDefenseCoverageChanges = (
  updates: Array<{ attackPatternId: string; previous: DefenseCoverage | undefined; coverage: DefenseCoverage }>,
): DefenseCoverageChange[] => {
  return updates
    .filter(({ previous }) => !!previous?.computed_at)
    .map(({ attackPatternId, previous, coverage }) => ({ attack_pattern_id: attackPatternId, previous: previous as DefenseCoverage, coverage }));
};

/**
 * The level change of a technique for one recipient: both coverages are evaluated with the evidences the recipient
 * can access, so a change caused only by a rule, a relationship or a result they cannot see is never reported.
 * Returns undefined when the level the recipient sees did not change.
 */
export const readerLevelChange = (change: DefenseCoverageChange, can: AccessPredicate): DefenseLevelChange | undefined => {
  const previousLevel = evaluateCoverage(change.attack_pattern_id, change.previous, can).level;
  const level = evaluateCoverage(change.attack_pattern_id, change.coverage, can).level;
  if (previousLevel === level) return undefined;
  return { attack_pattern_id: change.attack_pattern_id, previous_level: previousLevel, level };
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
 * "Defense level decreased" or "Defense level increased". Each recipient is told the change of the level they see:
 * the previous and the new coverage are evaluated with their own access to every evidence (an evidence deleted since
 * the previous computation counts with the markings it had, as kept in the trash). They must also be able to access
 * the technique and match the trigger filters, exactly as for knowledge events; digests built on these triggers collect
 * them like any live notification.
 * Returns the number of notified recipients. `progress` tells how far the delivery went, trigger by trigger, so a caller
 * keeps exactly what was not handled when a delivery fails; the triggers listed in `delivered_trigger_ids` of a change
 * are skipped.
 */
export const notifyDefenseLevelChanges = async (context: AuthContext, changes: DefenseCoverageChange[], progress?: DefenseDeliveryProgress) => {
  if (changes.length === 0) return 0;
  const liveNotifications = await getLiveNotifications(context);
  const listening = liveNotifications.filter(({ trigger }) => {
    const eventTypes = trigger.event_types ?? [];
    return eventTypes.includes(DEFENSE_TRIGGER_LEVEL_DECREASED) || eventTypes.includes(DEFENSE_TRIGGER_LEVEL_INCREASED);
  });
  if (listening.length === 0) return 0;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const evidenceIds = R.uniq(changes.flatMap((change) => [...collectCoverageIds(change.previous), ...collectCoverageIds(change.coverage)]));
  // One access evaluation per recipient for the whole computation, whatever the number of triggers they are in
  const predicates = new Map<string, Promise<AccessPredicate>>();
  const predicateOf = (userContext: AuthContext, user: AuthUser) => {
    let predicate = predicates.get(user.id);
    if (!predicate) {
      predicate = isBypassUser(user)
        ? Promise.resolve((id: string | undefined) => !!id)
        : findAccessibleIds(userContext, user, evidenceIds, { includeDeleted: true }).then((accessible) => (id: string | undefined) => !!id && accessible.has(id));
      predicates.set(user.id, predicate);
    }
    return predicate;
  };
  let delivered = 0;
  for (let changeIndex = 0; changeIndex < changes.length; changeIndex += 1) {
    await doYield();
    const change = changes[changeIndex];
    const handledTriggerIds = [...(change.delivered_trigger_ids ?? [])];
    if (progress) progress.triggerIds = handledTriggerIds;
    // The technique is loaded once, and only when a recipient has a change to be told
    const technique: { loaded: boolean; stix?: StixObject } = { loaded: false };
    const loadStix = async () => {
      if (!technique.loaded) {
        technique.stix = await stixLoadById(context, SYSTEM_USER, change.attack_pattern_id) as StixObject | undefined;
        technique.loaded = true;
      }
      return technique.stix;
    };
    for (let index = 0; index < listening.length; index += 1) {
      const { users, trigger } = listening[index];
      if (!handledTriggerIds.includes(trigger.internal_id)) {
        const eventTypes = trigger.event_types ?? [];
        const filters = trigger.filters ? JSON.parse(trigger.filters) : trigger.raw_filters;
        const targets: KnowledgeNotificationEvent['targets'] = [];
        for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
          const user: AuthUser = users[userIndex];
          const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
          const levelChange = readerLevelChange(change, await predicateOf(userContext, user));
          const eventType = levelChange ? defenseLevelEventType(levelChange) : undefined;
          if (levelChange && eventType && eventTypes.includes(eventType)) {
            const instance = await loadStix();
            if (instance && await isUserCanAccessStixElement(userContext, user, instance) && await isStixMatchFilterGroup(userContext, user, instance, filters)) {
              targets.push({ user: convertToNotificationUser(user, trigger.notifiers), type: eventType, message: buildDefenseLevelMessage(instance, levelChange) });
            }
          }
        }
        if (technique.stix && targets.length > 0) {
          const notificationEvent: KnowledgeNotificationEvent = {
            version: EVENT_NOTIFICATION_VERSION,
            notification_id: trigger.internal_id,
            type: 'live',
            targets,
            data: technique.stix,
            origin: { user_id: SYSTEM_USER.id },
          };
          await storeNotificationEvent(context, notificationEvent);
          delivered += targets.length;
        }
        handledTriggerIds.push(trigger.internal_id);
      }
    }
    if (progress) {
      progress.done = changeIndex + 1;
      progress.triggerIds = [];
    }
  }
  logApp.debug('[DEFENSE-COVERAGE] Defense level changes notified', { changes: changes.length, delivered });
  return delivered;
};

/**
 * The queued changes a failed delivery did not handle: the changes after the last fully handled one, the first of them
 * remembering the triggers already handled, so a retry never stores a notification twice.
 */
export const remainingDefenseLevelChanges = (changes: DefenseCoverageChange[], progress: DefenseDeliveryProgress): DefenseCoverageChange[] => {
  const remaining = changes.slice(progress.done);
  if (remaining.length > 0 && progress.triggerIds.length > 0) {
    remaining[0] = { ...remaining[0], delivered_trigger_ids: progress.triggerIds };
  }
  return remaining;
};

/**
 * Deliver the queued level changes, oldest computation first. A batch leaves the queue once delivered; when a delivery
 * fails, what it did not handle stays queued, the next batches wait behind it, and the next run retries.
 * Returns the number of notified recipients.
 */
export const deliverPendingDefenseLevelChanges = async (context: AuthContext, notify = notifyDefenseLevelChanges) => {
  const batches = await listPendingLevelChanges();
  let delivered = 0;
  for (let index = 0; index < batches.length; index += 1) {
    const { id, changes } = batches[index];
    if (!changes) {
      logApp.error('[DEFENSE-COVERAGE] Unreadable queued defense level changes dropped', { batch: id });
      await clearPendingLevelChanges(id);
    } else {
      const progress: DefenseDeliveryProgress = { done: 0, triggerIds: [] };
      try {
        delivered += await notify(context, changes, progress);
      } catch (error) {
        const remaining = remainingDefenseLevelChanges(changes, progress);
        if (progress.done > 0 || progress.triggerIds.length > 0) await replacePendingLevelChanges(id, remaining);
        logApp.error('[DEFENSE-COVERAGE] Defense level changes could not be notified, kept for the next run', { cause: error, pending: remaining.length });
        return delivered;
      }
      await clearPendingLevelChanges(id);
    }
  }
  return delivered;
};
