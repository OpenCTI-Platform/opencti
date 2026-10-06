import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { EXPIRATION_MANAGER_USER, executionContext } from '../utils/access';
import type { DataEvent, SseEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { RELATION_DEPLOYED_ON } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../modules/securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import {
  backfillIndicatorDeploymentCounters,
  reconcileDeployedIndicatorCounters,
  flagExpiredDeployments,
  reconcileAllIndicatorDeploymentCounters,
  reconcileIndicatorDeploymentCounters,
  refreshIndicatorDeploymentCounters,
  repairPairMarkings,
  repairRecentDeploymentCounters,
} from '../modules/indicatorDeployment/indicatorDeployment-domain';
import { maintainIocValidationRequests, repairValidationRequestAccess } from '../modules/iocValidation/iocValidation-domain';
import { redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';

const toPositiveNumber = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const INDICATOR_DEPLOYMENT_MANAGER_ENABLED = booleanConf('indicator_deployment_manager:enabled', true);
const INDICATOR_DEPLOYMENT_MANAGER_KEY = conf.get('indicator_deployment_manager:lock_key') || 'indicator_deployment_manager_lock';
const INDICATOR_DEPLOYMENT_MANAGER_STREAM_KEY = conf.get('indicator_deployment_manager:stream_lock_key') || 'indicator_deployment_manager_stream_lock';
const SCHEDULE_TIME = toPositiveNumber(conf.get('indicator_deployment_manager:interval'), 60000);
const BATCH_SIZE = toPositiveNumber(conf.get('indicator_deployment_manager:batch_size'), 1000);
const BACKFILL_BATCH_SIZE = toPositiveNumber(conf.get('indicator_deployment_manager:backfill_batch_size'), 10000);
// Time given to the connectors to confirm a removal before the deployment is flagged expired.
const REMOVAL_GRACE_PERIOD = toPositiveNumber(conf.get('indicator_deployment_manager:removal_grace_period'), 24 * 3600 * 1000);
// Bound of the full counters reconciliation run after a Security Platform deletion (pages of BATCH_SIZE indicators).
const RECONCILIATION_MAX_PAGES = toPositiveNumber(conf.get('indicator_deployment_manager:reconciliation_max_pages'), 1000);

const CONTEXT_NAME = 'indicator_deployment_manager';

export const indicatorDeploymentCronHandler = async () => {
  const context = executionContext(CONTEXT_NAME);
  const flagged = await flagExpiredDeployments(context, EXPIRATION_MANAGER_USER, REMOVAL_GRACE_PERIOD, BATCH_SIZE);
  const repaired = await repairRecentDeploymentCounters(context, SCHEDULE_TIME * 2, BATCH_SIZE);
  const reconciled = await reconcileIndicatorDeploymentCounters(context, BATCH_SIZE);
  const deployedReconciled = await reconcileDeployedIndicatorCounters(context, BATCH_SIZE);
  const requests = await maintainIocValidationRequests(context);
  const backfilled = await backfillIndicatorDeploymentCounters(context, BACKFILL_BATCH_SIZE);
  logApp.debug('[OPENCTI-MODULE] Indicator deployment manager run', { flagged, repaired, reconciled, deployedReconciled, requests, backfilled });
};

type DeploymentEventData = {
  type?: string;
  relationship_type?: string;
  revoked?: boolean;
  extensions?: Record<string, { id?: string; source_ref?: string; type?: string; deployment_platforms_count?: number }>;
};

// Whether the last event of each indicator in this batch showed it live on a platform.
export const extractStreamedDeploymentLive = (events: Array<SseEvent<DataEvent>>) => {
  const shown = new Map<string, boolean>();
  events.forEach((event) => {
    if (event.data?.type !== 'create' && event.data?.type !== 'update') return;
    const extension = (event.data.data as DeploymentEventData | undefined)?.extensions?.[STIX_EXT_OCTI];
    if (extension?.type === ENTITY_TYPE_INDICATOR && extension.id) {
      shown.set(extension.id, (extension.deployment_platforms_count ?? 0) > 0);
    }
  });
  return shown;
};

// Indicators revoked by an update of this batch: the revocation may have been streamed before the counters caught up.
export const extractRevokedIndicatorIds = (events: Array<SseEvent<DataEvent>>) => {
  const ids = new Set<string>();
  events.forEach((event) => {
    if (event.data?.type !== 'update') return;
    const data = event.data.data as DeploymentEventData | undefined;
    const extension = data?.extensions?.[STIX_EXT_OCTI];
    const patch = (event.data as unknown as { context?: { patch?: Array<{ path?: string }> } }).context?.patch ?? [];
    if (extension?.type === ENTITY_TYPE_INDICATOR && extension.id && data?.revoked === true && patch.some((operation) => operation.path === '/revoked')) {
      ids.add(extension.id);
    }
  });
  return [...ids];
};

// Indicators whose deployed-on relationships changed in this batch of events. A merge redirects the
// relationships of the merged indicators to the surviving one without relationship events.
export const extractDeploymentIndicatorIds = (events: Array<SseEvent<DataEvent>>) => {
  const ids = new Set<string>();
  events.forEach((event) => {
    const data = event.data?.data as DeploymentEventData | undefined;
    const extension = data?.extensions?.[STIX_EXT_OCTI];
    if (data?.type === 'relationship' && data.relationship_type === RELATION_DEPLOYED_ON) {
      if (extension?.source_ref) ids.add(extension.source_ref);
    } else if (event.data?.type === 'merge' && extension?.type === ENTITY_TYPE_INDICATOR && extension.id) {
      ids.add(extension.id);
    }
  });
  return [...ids];
};

// A Security Platform deleted or merged away takes its deployed-on relationships with it, without relationship events.
export const hasSecurityPlatformRemoval = (events: Array<SseEvent<DataEvent>>) => events.some((event) => {
  const data = event.data?.data as DeploymentEventData | undefined;
  const isRemoval = event.data?.type === 'delete' || event.data?.type === 'merge';
  return isRemoval && data?.extensions?.[STIX_EXT_OCTI]?.type === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM;
});

// Indicators and Security Platforms whose markings, sharing, authorized members or creator changed by an update, or that absorbed
// another one by a merge (the merged pair relationships move to them without any relationship event): their pair
// relationships carry the markings of both ends and the counters depend on the restrictions of both ends, so the
// relationships are repaired and the counters of the indicators recomputed.
export const extractAccessChangedEndpoints = (events: Array<SseEvent<DataEvent>>) => {
  const indicatorIds = new Set<string>();
  const platformIds = new Set<string>();
  events.forEach((event) => {
    const isMerge = event.data?.type === 'merge';
    if (event.data?.type !== 'update' && !isMerge) return;
    const patch = (event.data as unknown as { context?: { patch?: Array<{ path?: string }> } }).context?.patch ?? [];
    const accessPaths = ['object_marking_refs', 'granted_refs', 'authorized_members', 'created_by_ref'];
    if (!isMerge && !patch.some((operation) => accessPaths.some((path) => operation.path?.includes(path)))) return;
    const data = event.data.data as DeploymentEventData | undefined;
    const extension = data?.extensions?.[STIX_EXT_OCTI];
    // A marking removed from a deployment itself is given back from its ends, through its indicator
    if (data?.type === 'relationship' && data.relationship_type === RELATION_DEPLOYED_ON) {
      if (extension?.source_ref) indicatorIds.add(extension.source_ref);
      return;
    }
    if (!extension?.id) return;
    if (extension.type === ENTITY_TYPE_INDICATOR) indicatorIds.add(extension.id);
    if (extension.type === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM) platformIds.add(extension.id);
  });
  return { indicatorIds: [...indicatorIds], platformIds: [...platformIds] };
};

export const indicatorDeploymentStreamHandler = async (events: Array<SseEvent<DataEvent>>, lastEventId: string) => {
  const indicatorIds = [...new Set([...extractDeploymentIndicatorIds(events), ...extractRevokedIndicatorIds(events)])];
  if (indicatorIds.length > 0) {
    const context = executionContext(CONTEXT_NAME);
    await refreshIndicatorDeploymentCounters(context, indicatorIds, extractStreamedDeploymentLive(events));
  }
  const markingChanges = extractAccessChangedEndpoints(events);
  if (markingChanges.indicatorIds.length > 0 || markingChanges.platformIds.length > 0) {
    const context = executionContext(CONTEXT_NAME);
    const repaired = await repairPairMarkings(context, EXPIRATION_MANAGER_USER, markingChanges);
    const requests = await repairValidationRequestAccess(context, EXPIRATION_MANAGER_USER, markingChanges);
    logApp.info('[OPENCTI-MODULE] Deployment markings and counters repaired after an endpoint access change', { repaired, requests });
  }
  if (hasSecurityPlatformRemoval(events)) {
    const context = executionContext(CONTEXT_NAME);
    const updated = await reconcileAllIndicatorDeploymentCounters(context, BATCH_SIZE, RECONCILIATION_MAX_PAGES);
    logApp.info('[OPENCTI-MODULE] Indicator deployment counters reconciled after a security platform removal', { updated });
  }
  // Saved after the refresh so a restart replays the events received while the manager was stopped.
  if (lastEventId) {
    await redisSetManagerEventState(CONTEXT_NAME, lastEventId);
  }
};

export const indicatorDeploymentStreamStartFrom = async () => {
  return (await redisGetManagerEventState(CONTEXT_NAME)) ?? 'live';
};

const INDICATOR_DEPLOYMENT_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'INDICATOR_DEPLOYMENT_MANAGER',
  label: 'Indicator deployment manager',
  executionContext: CONTEXT_NAME,
  cronSchedulerHandler: {
    handler: indicatorDeploymentCronHandler,
    interval: SCHEDULE_TIME,
    lockKey: INDICATOR_DEPLOYMENT_MANAGER_KEY,
  },
  streamSchedulerHandler: {
    handler: indicatorDeploymentStreamHandler,
    interval: SCHEDULE_TIME,
    lockKey: INDICATOR_DEPLOYMENT_MANAGER_STREAM_KEY,
    streamOpts: { bufferTime: 2000 },
    streamProcessorStartFrom: indicatorDeploymentStreamStartFrom,
  },
  enabledByConfig: INDICATOR_DEPLOYMENT_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(INDICATOR_DEPLOYMENT_MANAGER_DEFINITION);
