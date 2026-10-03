import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { EXPIRATION_MANAGER_USER, executionContext } from '../utils/access';
import type { DataEvent, SseEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { RELATION_DEPLOYED_ON } from '../schema/stixCoreRelationship';
import {
  backfillIndicatorDeploymentCounters,
  flagExpiredDeployments,
  refreshIndicatorDeploymentCounters,
  repairRecentDeploymentCounters,
} from '../modules/indicatorDeployment/indicatorDeployment-domain';
import { maintainIocValidationRequests } from '../modules/iocValidation/iocValidation-domain';
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

const CONTEXT_NAME = 'indicator_deployment_manager';

export const indicatorDeploymentCronHandler = async () => {
  const context = executionContext(CONTEXT_NAME);
  const flagged = await flagExpiredDeployments(context, EXPIRATION_MANAGER_USER, REMOVAL_GRACE_PERIOD, BATCH_SIZE);
  const repaired = await repairRecentDeploymentCounters(context, SCHEDULE_TIME * 2, BATCH_SIZE);
  const requests = await maintainIocValidationRequests(context);
  const backfilled = await backfillIndicatorDeploymentCounters(BACKFILL_BATCH_SIZE);
  logApp.debug('[OPENCTI-MODULE] Indicator deployment manager run', { flagged, repaired, requests, backfilled });
};

// Indicators whose deployed-on relationships changed in this batch of events.
export const extractDeploymentIndicatorIds = (events: Array<SseEvent<DataEvent>>) => {
  const ids = new Set<string>();
  events.forEach((event) => {
    const data = event.data?.data as { type?: string; relationship_type?: string; extensions?: Record<string, { source_ref?: string }> } | undefined;
    if (data?.type === 'relationship' && data.relationship_type === RELATION_DEPLOYED_ON) {
      const sourceRef = data.extensions?.[STIX_EXT_OCTI]?.source_ref;
      if (sourceRef) ids.add(sourceRef);
    }
  });
  return [...ids];
};

export const indicatorDeploymentStreamHandler = async (events: Array<SseEvent<DataEvent>>, lastEventId: string) => {
  const indicatorIds = extractDeploymentIndicatorIds(events);
  if (indicatorIds.length > 0) {
    const context = executionContext(CONTEXT_NAME);
    await refreshIndicatorDeploymentCounters(context, indicatorIds);
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
