import type { AuthContext } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import type { StixObject } from '../../../types/stix-2-1-common';
import { logApp } from '../../../config/conf';
import { getEntityFromCache } from '../../../database/cache';
import { stixLoadById } from '../../../database/middleware';
import { storeNotificationEvent } from '../../../database/stream/stream-handler';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { isUserInPlatformOrganization, PULSE_MANAGER_USER, SYSTEM_USER } from '../../../utils/access';
import { isStixMatchFilterGroup } from '../../../utils/filtering/filtering-stix/stix-filtering';
import {
  convertToNotificationUser,
  EVENT_NOTIFICATION_VERSION,
  generateNotificationMessageForInstance,
  getLiveNotifications,
  type KnowledgeNotificationEvent,
  type ResolvedLive,
} from '../../../manager/notificationManager';
import { ENTITY_TYPE_TRIGGER } from '../../notification/notification-types';
import { PulsePeriod, PulseSectorBucket, PulseTrend, TriggerEventType } from '../../../generated/graphql';
import { getHubTrending, resolveTrendingEntries } from './pulse-domain';
import { buildPulseMarkingPolicy, getPulseHubPlatform, isPulseContributable, isPulseReading, readPulseSettings } from './pulse-settings';
import { redisFilterNewlyTrending, redisMarkTrendingNotified } from './pulse-cache';
import { PULSE_OBJECT_TYPE_BY_ENTITY_TYPE } from './pulse-types';

export const PULSE_TRENDING_EVENT_TYPE = TriggerEventType.PulseTrending;
// An object notified as trending is not notified again for this many days.
const TRENDING_NOTIFICATION_MEMORY_DAYS = 7;
const TRENDING_NOTIFICATION_SIZE = 200;

const isPulseTrendingTrigger = ({ trigger }: ResolvedLive) => {
  return trigger.entity_type === ENTITY_TYPE_TRIGGER && (trigger.event_types ?? []).includes(PULSE_TRENDING_EVENT_TYPE);
};

// Notifies the live triggers listening to "trending in my sector" for local objects that started rising in the
// platform's sector bucket. Digests aggregate these events like any other live notification.
export const runPulseTrendingNotifications = async (context: AuthContext) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const values = readPulseSettings(settings);
  const platform = getPulseHubPlatform(settings);
  if (!isPulseReading(values) || !platform || !values.sectorBucket || values.sectorBucket === PulseSectorBucket.Undisclosed) {
    return 0;
  }
  const triggers = (await getLiveNotifications(context)).filter(isPulseTrendingTrigger);
  if (triggers.length === 0) {
    return 0;
  }
  const result = await getHubTrending(platform, {
    period: PulsePeriod.Last_7Days,
    sector_bucket: values.sectorBucket,
    region_bucket: null,
    object_types: values.scopes.map((scope) => PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[scope]),
    first: TRENDING_NOTIFICATION_SIZE,
  });
  const policy = await buildPulseMarkingPolicy(context, values);
  const rising = (await resolveTrendingEntries(context, PULSE_MANAGER_USER, platform, result, values.scopes))
    .filter((entry) => entry.trend === PulseTrend.Rising && isPulseContributable(entry.entity, policy, values.scopes));
  const newIds = new Set(await redisFilterNewlyTrending(rising.map((entry) => entry.entity.internal_id), TRENDING_NOTIFICATION_MEMORY_DAYS));
  const fresh = rising.filter((entry) => newIds.has(entry.entity.internal_id));
  let notifications = 0;
  for (let entryIndex = 0; entryIndex < fresh.length; entryIndex += 1) {
    const entry = fresh[entryIndex];
    const stix = await stixLoadById(context, PULSE_MANAGER_USER, entry.entity.internal_id) as StixObject | null;
    if (!stix) {
      continue;
    }
    for (let triggerIndex = 0; triggerIndex < triggers.length; triggerIndex += 1) {
      const { users, trigger } = triggers[triggerIndex];
      const filters = trigger.filters ? JSON.parse(trigger.filters) : undefined;
      const targets: KnowledgeNotificationEvent['targets'] = [];
      for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
        const user = users[userIndex];
        const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
        if (await isStixMatchFilterGroup(userContext, user, stix, filters)) {
          const instanceMessage = await generateNotificationMessageForInstance(userContext, user, stix);
          targets.push({
            user: convertToNotificationUser(user, trigger.notifiers),
            type: PULSE_TRENDING_EVENT_TYPE,
            message: `${instanceMessage} is trending in your sector (${entry.platforms_bucket} platforms)`,
          });
        }
      }
      if (targets.length > 0) {
        const event: KnowledgeNotificationEvent = {
          version: EVENT_NOTIFICATION_VERSION,
          notification_id: trigger.internal_id,
          type: 'live',
          targets,
          data: stix,
          origin: { user_id: PULSE_MANAGER_USER.id, socket: 'internal' },
        };
        await storeNotificationEvent(context, event);
        notifications += targets.length;
      }
    }
  }
  await redisMarkTrendingNotified(fresh.map((entry) => entry.entity.internal_id));
  if (notifications > 0) {
    logApp.info('[THREAT PULSE] Trending notifications sent', { objects: fresh.length, notifications });
  }
  return notifications;
};
