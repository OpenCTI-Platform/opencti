import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, StoreObject } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import type { StixObject } from '../../types/stix-2-1-common';
import { isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { elList } from '../../database/engine';
import { storeLoadByIdsWithRefs } from '../../database/middleware';
import { convertStoreToStix } from '../../database/stix-common-converter';
import { getEntityFromCache } from '../../database/cache';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { extractStixRepresentative } from '../../database/stix-representative';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { convertToNotificationUser, EVENT_NOTIFICATION_VERSION, getLiveNotifications, type KnowledgeNotificationEvent } from '../../manager/notificationManager';
import { FilterMode, TriggerEventType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { GRAPH_METRICS_ENTITY_INDICES, loadGraphClusters } from './graphAnalytics-store';
import { GRAPH_METRICS_ATTRIBUTE, type GraphMetrics } from './graphAnalytics-types';

export const GRAPH_TRIGGER_CLUSTER_JOINED = TriggerEventType.GraphClusterJoined;
// A run moving more entities is a recomputation of the graph, not news: only that many members are notified
export const CLUSTER_JOINED_NOTIFICATION_MAX = 1000;

export const buildClusterJoinedMessage = (memberRepresentative: string, clusterName: string) => {
  return `[graph analytics] \`${memberRepresentative}\` joined the cluster \`${clusterName}\``;
};

/**
 * Deliver graph_cluster_joined to the live triggers listening to it, for the entities that joined a cluster when the
 * run published at `publishedAt`. Every recipient must be able to access the entity and match the trigger filters,
 * exactly as for knowledge events; the message only names the entity and the cluster, never counts of members.
 */
export const notifyGraphClusterJoined = async (context: AuthContext, publishedAt: string): Promise<number> => {
  const liveNotifications = await getLiveNotifications(context);
  const candidates = liveNotifications.filter(({ trigger }) => (trigger.event_types ?? []).includes(GRAPH_TRIGGER_CLUSTER_JOINED));
  if (candidates.length === 0) return 0;
  const joined = await elList<BasicStoreBase>(context, SYSTEM_USER, GRAPH_METRICS_ENTITY_INDICES, {
    types: [ABSTRACT_STIX_CORE_OBJECT],
    filters: { mode: FilterMode.And, filters: [{ key: [`${GRAPH_METRICS_ATTRIBUTE}.cluster_joined_at`], values: [publishedAt] }], filterGroups: [] },
    noFiltersChecking: true,
    baseData: true,
    baseFields: [GRAPH_METRICS_ATTRIBUTE],
    maxSize: CLUSTER_JOINED_NOTIFICATION_MAX + 1,
  });
  if (joined.length > CLUSTER_JOINED_NOTIFICATION_MAX) {
    logApp.info('[OPENCTI-MODULE] Graph analytics cluster notifications skipped, too many entities joined a cluster in one run', { max: CLUSTER_JOINED_NOTIFICATION_MAX });
    return 0;
  }
  const metricsOf = (element: BasicStoreBase) => (element as unknown as Record<string, GraphMetrics | undefined>)[GRAPH_METRICS_ATTRIBUTE];
  const clusterIds = Array.from(new Set(joined.map((element) => metricsOf(element)?.cluster_id).filter((id): id is string => !!id)));
  const clusters = new Map((await loadGraphClusters(context, SYSTEM_USER, clusterIds)).map((cluster) => [cluster.internal_id, cluster]));
  const memberIds = joined.filter((element) => clusters.has(metricsOf(element)?.cluster_id ?? '')).map((element) => element.internal_id);
  const members = memberIds.length > 0 ? await storeLoadByIdsWithRefs<StoreObject>(context, SYSTEM_USER, memberIds) : [];
  const membersById = new Map(members.map((member) => [member.internal_id, member]));
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  let delivered = 0;
  for (let index = 0; index < joined.length; index += 1) {
    const cluster = clusters.get(metricsOf(joined[index])?.cluster_id ?? '');
    const member = membersById.get(joined[index].internal_id);
    if (!cluster || !member) continue;
    const stix = convertStoreToStix(member) as StixObject;
    const message = buildClusterJoinedMessage(extractStixRepresentative(stix), cluster.name);
    for (let triggerIndex = 0; triggerIndex < candidates.length; triggerIndex += 1) {
      const { users, trigger } = candidates[triggerIndex];
      const filters = trigger.filters ? JSON.parse(trigger.filters) : trigger.raw_filters;
      const targets: KnowledgeNotificationEvent['targets'] = [];
      for (let userIndex = 0; userIndex < users.length; userIndex += 1) {
        const user: AuthUser = users[userIndex];
        const userContext = { ...context, user_inside_platform_organization: isUserInPlatformOrganization(user, settings) };
        if (await isUserCanAccessStixElement(userContext, user, stix) && await isStixMatchFilterGroup(userContext, user, stix, filters)) {
          targets.push({ user: convertToNotificationUser(user, trigger.notifiers), type: GRAPH_TRIGGER_CLUSTER_JOINED, message });
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
  return delivered;
};

/** Notifications of a published run, which they never fail. */
export const notifyClusterMemberships = async (context: AuthContext, publishedAt: string): Promise<number> => {
  try {
    return await notifyGraphClusterJoined(context, publishedAt);
  } catch (err) {
    logApp.error('[OPENCTI-MODULE] Graph analytics cluster notifications fail', { cause: err });
    return 0;
  }
};
