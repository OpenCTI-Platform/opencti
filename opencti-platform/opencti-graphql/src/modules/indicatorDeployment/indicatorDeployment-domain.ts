import { v5 as uuidv5 } from 'uuid';
import { Promise as BluePromise } from 'bluebird';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreRelation } from '../../types/store';
import { createRelation, distributionRelations, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, fullRelationsList, internalLoadById, storeLoadById, topRelationsList } from '../../database/middleware-loader';
import { buildReplaceScriptParams, EL_REPLACE_SCRIPT_SOURCE, elAggregationCount, elCount, elRawUpdateByQuery, elUpdate } from '../../database/engine';
import { isEmptyField, isNotEmptyField, READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../../database/utils';
import { lockResources } from '../../lock/master-lock';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError, ValidationError } from '../../config/errors';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, INPUT_MARKINGS, OPENCTI_NAMESPACE } from '../../schema/general';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_INDICATOR, type BasicStoreEntityIndicator } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../securityPlatform/securityPlatform-types';
import { SYSTEM_USER } from '../../utils/access';
import { addIndicatorDeploymentReportCount, addIndicatorHitsReportCount } from '../../manager/telemetryManager';
import type { IndicatorDeploymentBatchResult, IndicatorDeploymentMetadataInput, IndicatorDeploymentReportInput, IndicatorDeploymentStatus } from '../../generated/graphql';
import {
  type BasicStoreRelationDeployedOn,
  type DeployedOnAttributes,
  DEPLOYMENT_STATUS_ACTIVE,
  DEPLOYMENT_STATUS_DEPLOYED,
  DEPLOYMENT_STATUS_EXPIRED,
  DEPLOYMENT_STATUS_FAILED,
  DEPLOYMENT_STATUS_PENDING,
  DEPLOYMENT_STATUS_REMOVED,
  type DeploymentStatus,
  INDICATOR_DEPLOYMENT_FAILED_COUNT,
  INDICATOR_DEPLOYMENT_PLATFORMS_COUNT,
  INDICATOR_HIT_PLATFORMS_COUNT,
  INDICATOR_VALIDATED_PLATFORMS_COUNT,
  type IndicatorDeploymentCounters,
  LIVE_DEPLOYMENT_STATUSES,
  PROVEN_VALIDATION_STATUSES,
  RELATION_DEPLOYED_ON,
} from './indicatorDeployment-types';
import { isDeploymentStatus } from './indicatorDeployment-utils';
import { consumeDeploymentRateLimit, DEPLOYMENT_RATE_LIMIT_BATCH, DEPLOYMENT_RATE_LIMIT_HITS, DEPLOYMENT_RATE_LIMIT_SINGLE } from './indicatorDeployment-rate-limit';

export const DEPLOYMENT_BATCH_MAX_SIZE = 500;
const EXTERNAL_ID_MAX_LENGTH = 1000;
const ERROR_MESSAGE_MAX_LENGTH = 5000;
const BATCH_CONCURRENCY = 5;
// Namespace of the stable hits sighting identifier (one sighting per indicator and security platform).
const HITS_SIGHTING_NAMESPACE = uuidv5('opencti-indicator-deployment-hits', OPENCTI_NAMESPACE);

type DateInput = Date | string | null | undefined;

// region pure lifecycle rules
export interface DeploymentReport {
  status: DeploymentStatus;
  externalId?: string | null;
  deployedAt?: DateInput;
  syncedAt?: DateInput;
  removedAt?: DateInput;
  errorMessage?: string | null;
}

export interface DeploymentChange {
  // Attributes to write. Always contains last_sync_at.
  attributes: Partial<Record<keyof DeployedOnAttributes, unknown>>;
  // True when the change must go through the regular update path (history, stream event, triggers).
  meaningful: boolean;
}

const toDate = (value: DateInput, fallback: Date): Date => {
  if (isEmptyField(value)) {
    return fallback;
  }
  const date = value instanceof Date ? value : new Date(value as string);
  if (Number.isNaN(date.getTime())) {
    throw ValidationError('Invalid date in deployment report', 'metadata', { value });
  }
  return date;
};

const isLive = (status: string | undefined | null) => LIVE_DEPLOYMENT_STATUSES.includes(status as DeploymentStatus);

/**
 * Resolve the status to store from the reported one.
 * - A re-push (deployed) never downgrades an indicator already confirmed active.
 * - A pending report never downgrades a live deployment.
 */
export const resolveEffectiveStatus = (currentStatus: string | undefined | null, reportedStatus: DeploymentStatus): DeploymentStatus => {
  if (reportedStatus === DEPLOYMENT_STATUS_DEPLOYED && currentStatus === DEPLOYMENT_STATUS_ACTIVE) {
    return DEPLOYMENT_STATUS_ACTIVE;
  }
  if (reportedStatus === DEPLOYMENT_STATUS_PENDING && isLive(currentStatus)) {
    return currentStatus as DeploymentStatus;
  }
  return reportedStatus;
};

/**
 * Compute the deployed-on attributes resulting from a connector report.
 * When current is undefined the result describes the creation of the relationship.
 */
export const computeDeploymentChange = (
  current: Partial<DeployedOnAttributes> | undefined,
  report: DeploymentReport,
  now: Date,
): DeploymentChange => {
  if (!isDeploymentStatus(report.status) || report.status === DEPLOYMENT_STATUS_EXPIRED) {
    throw ValidationError('Deployment status is invalid or reserved to the platform', 'status', { status: report.status });
  }
  if (isNotEmptyField(report.externalId) && String(report.externalId).length > EXTERNAL_ID_MAX_LENGTH) {
    throw ValidationError(`External id cannot exceed ${EXTERNAL_ID_MAX_LENGTH} characters`, 'externalId');
  }
  if (isNotEmptyField(report.errorMessage) && String(report.errorMessage).length > ERROR_MESSAGE_MAX_LENGTH) {
    throw ValidationError(`Error message cannot exceed ${ERROR_MESSAGE_MAX_LENGTH} characters`, 'error_message');
  }
  const syncedAt = toDate(report.syncedAt, now);
  const status = resolveEffectiveStatus(current?.deployment_status, report.status);
  const errorMessage = status === DEPLOYMENT_STATUS_FAILED && isNotEmptyField(report.errorMessage) ? report.errorMessage : null;
  if (!current) {
    const attributes: DeploymentChange['attributes'] = { deployment_status: status, last_sync_at: syncedAt };
    if (isNotEmptyField(report.externalId)) attributes.external_id = report.externalId;
    if (isLive(status)) attributes.deployed_at = toDate(report.deployedAt, now);
    if (status === DEPLOYMENT_STATUS_REMOVED) attributes.removed_at = toDate(report.removedAt, now);
    if (errorMessage) attributes.error_message = errorMessage;
    return { attributes, meaningful: true };
  }
  const patch: DeploymentChange['attributes'] = {};
  if (status !== current.deployment_status) {
    patch.deployment_status = status;
  }
  if (isLive(status) && !isLive(current.deployment_status)) {
    patch.deployed_at = toDate(report.deployedAt, now);
    if (isNotEmptyField(current.removed_at)) patch.removed_at = null;
  } else if (isLive(status) && isEmptyField(current.deployed_at)) {
    patch.deployed_at = toDate(report.deployedAt, now);
  }
  if (status === DEPLOYMENT_STATUS_REMOVED && current.deployment_status !== DEPLOYMENT_STATUS_REMOVED) {
    patch.removed_at = toDate(report.removedAt, now);
  }
  if (isNotEmptyField(report.externalId) && report.externalId !== current.external_id) {
    patch.external_id = report.externalId;
  }
  if ((errorMessage ?? null) !== (current.error_message ?? null)) {
    patch.error_message = errorMessage;
  }
  const meaningful = Object.keys(patch).length > 0;
  return { attributes: { ...patch, last_sync_at: syncedAt }, meaningful };
};

export const computeIndicatorDeploymentCounters = (relations: Array<Partial<DeployedOnAttributes>>): IndicatorDeploymentCounters => {
  return {
    [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT]: relations.filter((r) => isLive(r.deployment_status)).length,
    [INDICATOR_DEPLOYMENT_FAILED_COUNT]: relations.filter((r) => r.deployment_status === DEPLOYMENT_STATUS_FAILED).length,
    [INDICATOR_VALIDATED_PLATFORMS_COUNT]: relations.filter((r) => PROVEN_VALIDATION_STATUSES.includes(r.validation_status as never)).length,
    [INDICATOR_HIT_PLATFORMS_COUNT]: relations.filter((r) => (r.hit_count ?? 0) > 0).length,
  };
};

export const hitsSightingStixId = (indicatorInternalId: string, platformInternalId: string) => {
  return `sighting--${uuidv5(`${indicatorInternalId}|${platformInternalId}`, HITS_SIGHTING_NAMESPACE)}`;
};
// endregion

// region loaders
const loadIndicator = async (context: AuthContext, user: AuthUser, indicatorId: string) => {
  const indicator = await storeLoadById<BasicStoreEntityIndicator>(context, user, indicatorId, ENTITY_TYPE_INDICATOR);
  if (!indicator) {
    throw FunctionalError('Indicator not found or not accessible', { indicatorId });
  }
  return indicator;
};

const loadSecurityPlatform = async (context: AuthContext, user: AuthUser, platformId: string) => {
  const platform = await storeLoadById<BasicStoreEntitySecurityPlatform>(context, user, platformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  if (!platform) {
    throw FunctionalError('Security platform not found or not accessible', { platformId });
  }
  return platform;
};

export const findDeployedOn = async (context: AuthContext, user: AuthUser, indicatorInternalId: string, platformInternalId: string) => {
  const relations = await topRelationsList<BasicStoreRelationDeployedOn & { _index: string }>(context, user, RELATION_DEPLOYED_ON, {
    fromId: indicatorInternalId,
    toId: platformInternalId,
    first: 1,
  });
  return relations.length > 0 ? relations[0] : undefined;
};

export const loadDeployedOnById = async (context: AuthContext, user: AuthUser, id: string) => {
  const relation = await storeLoadById<BasicStoreRelationDeployedOn>(context, user, id, RELATION_DEPLOYED_ON);
  if (!relation) {
    throw FunctionalError('Deployment not found or not accessible', { id });
  }
  return relation;
};
// endregion

// region writes
const touchLastSync = async (context: AuthContext, relation: BasicStoreRelation, lastSyncAt: unknown) => {
  // Heartbeat only: side-channel update, no stream event, no history, updated_at kept.
  const params = buildReplaceScriptParams({ last_sync_at: lastSyncAt });
  await elUpdate(context, relation._index, relation.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
};

const notifyRelationEdit = async (user: AuthUser, element: unknown) => {
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, element, user);
};

type ReportOutcome = 'created' | 'updated' | 'unchanged';

// Serializes every write on one (indicator, platform) pair. Never an entity id: createRelation locks the ids
// of the elements it writes, and locking one of them here would make the nested creation wait on this lock.
const pairLockKey = (indicatorInternalId: string, platformInternalId: string) => `deployed-on-${indicatorInternalId}-${platformInternalId}`;

const applyDeploymentReport = async (
  context: AuthContext,
  user: AuthUser,
  indicator: BasicStoreEntityIndicator,
  platform: BasicStoreEntitySecurityPlatform,
  report: DeploymentReport,
): Promise<{ element: BasicStoreRelationDeployedOn; outcome: ReportOutcome }> => {
  const lock = await lockResources([pairLockKey(indicator.internal_id, platform.internal_id)]);
  try {
    const now = new Date();
    const existing = await findDeployedOn(context, user, indicator.internal_id, platform.internal_id);
    const change = computeDeploymentChange(existing, report, now);
    if (!existing) {
      const element = await createRelation(context, user, {
        fromId: indicator.internal_id,
        toId: platform.internal_id,
        relationship_type: RELATION_DEPLOYED_ON,
        [INPUT_MARKINGS]: indicator[RELATION_OBJECT_MARKING] ?? [],
        ...change.attributes,
      }) as unknown as BasicStoreRelationDeployedOn;
      return { element, outcome: 'created' };
    }
    if (!change.meaningful) {
      await touchLastSync(context, existing, change.attributes.last_sync_at);
      return { element: { ...existing, last_sync_at: change.attributes.last_sync_at as Date }, outcome: 'unchanged' };
    }
    const { element } = await patchAttribute(context, user, existing.internal_id, RELATION_DEPLOYED_ON, change.attributes);
    await notifyRelationEdit(user, element);
    return { element: element as unknown as BasicStoreRelationDeployedOn, outcome: 'updated' };
  } finally {
    await lock.unlock();
  }
};

const toReport = (status: IndicatorDeploymentStatus, externalId?: string | null, metadata?: IndicatorDeploymentMetadataInput | null): DeploymentReport => ({
  status: status as DeploymentStatus,
  externalId,
  deployedAt: metadata?.deployed_at,
  syncedAt: metadata?.last_sync_at,
  removedAt: metadata?.removed_at,
  errorMessage: metadata?.error_message,
});

export interface ReportDeploymentArgs {
  indicatorId: string;
  platformId: string;
  status: IndicatorDeploymentStatus;
  externalId?: string | null;
  metadata?: IndicatorDeploymentMetadataInput | null;
}

export const reportIndicatorDeployment = async (context: AuthContext, user: AuthUser, args: ReportDeploymentArgs) => {
  await consumeDeploymentRateLimit(DEPLOYMENT_RATE_LIMIT_SINGLE, user);
  const report = toReport(args.status, args.externalId, args.metadata);
  // Validate before any read
  computeDeploymentChange(undefined, report, new Date());
  const [indicator, platform] = await Promise.all([
    loadIndicator(context, user, args.indicatorId),
    loadSecurityPlatform(context, user, args.platformId),
  ]);
  const { element } = await applyDeploymentReport(context, user, indicator, platform, report);
  await addIndicatorDeploymentReportCount();
  return element;
};

export const reportIndicatorDeployments = async (
  context: AuthContext,
  user: AuthUser,
  platformId: string,
  reports: IndicatorDeploymentReportInput[],
): Promise<IndicatorDeploymentBatchResult> => {
  await consumeDeploymentRateLimit(DEPLOYMENT_RATE_LIMIT_BATCH, user);
  if (reports.length > DEPLOYMENT_BATCH_MAX_SIZE) {
    throw ValidationError(`A deployment batch cannot exceed ${DEPLOYMENT_BATCH_MAX_SIZE} reports`, 'reports', { size: reports.length });
  }
  const platform = await loadSecurityPlatform(context, user, platformId);
  const result: IndicatorDeploymentBatchResult = { processed: 0, created: 0, updated: 0, unchanged: 0, errors: [] };
  await BluePromise.map(reports, async (input) => {
    try {
      const report = toReport(input.status, input.externalId, input.metadata);
      computeDeploymentChange(undefined, report, new Date());
      const indicator = await loadIndicator(context, user, input.indicatorId);
      const { outcome } = await applyDeploymentReport(context, user, indicator, platform, report);
      result.processed += 1;
      result[outcome] += 1;
    } catch (error) {
      const message = (error as { message?: string }).message ?? 'Unknown error';
      result.errors.push({ indicatorId: input.indicatorId, message });
    }
  }, { concurrency: BATCH_CONCURRENCY });
  if (result.processed > 0) {
    await addIndicatorDeploymentReportCount(result.processed);
  }
  if (result.errors.length > 0) {
    logApp.warn('[DISSEMINATION] Deployment batch processed with errors', { platformId: platform.internal_id, errors: result.errors.length, processed: result.processed });
  }
  return result;
};

export interface ReportHitsArgs {
  indicatorId: string;
  platformId: string;
  count: number;
  lastHit?: DateInput;
  firstHit?: DateInput;
}

export const reportIndicatorHits = async (context: AuthContext, user: AuthUser, args: ReportHitsArgs) => {
  await consumeDeploymentRateLimit(DEPLOYMENT_RATE_LIMIT_HITS, user);
  if (!Number.isInteger(args.count) || args.count < 1) {
    throw ValidationError('Hit count must be a positive integer', 'count', { count: args.count });
  }
  const now = new Date();
  const lastHit = toDate(args.lastHit, now);
  const firstHit = toDate(args.firstHit, lastHit);
  if (firstHit.getTime() > lastHit.getTime()) {
    throw ValidationError('First hit cannot be after last hit', 'firstHit');
  }
  const [indicator, platform] = await Promise.all([
    loadIndicator(context, user, args.indicatorId),
    loadSecurityPlatform(context, user, args.platformId),
  ]);
  const sightingStixId = hitsSightingStixId(indicator.internal_id, platform.internal_id);
  const lock = await lockResources([pairLockKey(indicator.internal_id, platform.internal_id)]);
  try {
    const existing = await findDeployedOn(context, user, indicator.internal_id, platform.internal_id);
    const existingSighting = await internalLoadById<BasicStoreRelation & { attribute_count?: number; first_seen?: string; last_seen?: string }>(
      context,
      user,
      sightingStixId,
      { type: STIX_SIGHTING_RELATIONSHIP },
    );
    const lastKnownHit = existing?.last_hit_at ? new Date(existing.last_hit_at).getTime() : undefined;
    if (existingSighting && lastKnownHit !== undefined && lastHit.getTime() <= lastKnownHit) {
      // Replay of an already counted report: idempotent no-op.
      return existingSighting;
    }
    // 01. Deployment state: hits prove the indicator is live on the platform
    if (!existing) {
      await createRelation(context, user, {
        fromId: indicator.internal_id,
        toId: platform.internal_id,
        relationship_type: RELATION_DEPLOYED_ON,
        [INPUT_MARKINGS]: indicator[RELATION_OBJECT_MARKING] ?? [],
        deployment_status: DEPLOYMENT_STATUS_ACTIVE,
        deployed_at: firstHit,
        last_sync_at: now,
        hit_count: args.count,
        last_hit_at: lastHit,
      });
    } else {
      const patch: Record<string, unknown> = { hit_count: (existing.hit_count ?? 0) + args.count, last_hit_at: lastHit, last_sync_at: now };
      const removedBeforeHit = existing.deployment_status === DEPLOYMENT_STATUS_REMOVED
        && (!existing.removed_at || new Date(existing.removed_at).getTime() < lastHit.getTime());
      const promotable = [DEPLOYMENT_STATUS_PENDING, DEPLOYMENT_STATUS_DEPLOYED, DEPLOYMENT_STATUS_FAILED].includes(existing.deployment_status as never);
      if (promotable || removedBeforeHit) {
        patch.deployment_status = DEPLOYMENT_STATUS_ACTIVE;
        patch.error_message = null;
        if (isEmptyField(existing.deployed_at) || removedBeforeHit) patch.deployed_at = firstHit;
        if (removedBeforeHit) patch.removed_at = null;
      }
      const { element } = await patchAttribute(context, user, existing.internal_id, RELATION_DEPLOYED_ON, patch);
      await notifyRelationEdit(user, element);
    }
    // 02. Stable hits sighting Indicator -> Security Platform
    let sighting;
    if (!existingSighting) {
      sighting = await createRelation(context, user, {
        fromId: indicator.internal_id,
        toId: platform.internal_id,
        relationship_type: STIX_SIGHTING_RELATIONSHIP,
        stix_id: sightingStixId,
        [INPUT_MARKINGS]: indicator[RELATION_OBJECT_MARKING] ?? [],
        attribute_count: args.count,
        first_seen: firstHit,
        last_seen: lastHit,
        x_opencti_negative: false,
        description: `Hits reported by the ${platform.name} integration`,
      });
    } else {
      const previousFirst = existingSighting.first_seen ? new Date(existingSighting.first_seen).getTime() : firstHit.getTime();
      const previousLast = existingSighting.last_seen ? new Date(existingSighting.last_seen).getTime() : lastHit.getTime();
      const { element } = await patchAttribute(context, user, existingSighting.internal_id, STIX_SIGHTING_RELATIONSHIP, {
        attribute_count: (existingSighting.attribute_count ?? 0) + args.count,
        first_seen: new Date(Math.min(previousFirst, firstHit.getTime())),
        last_seen: new Date(Math.max(previousLast, lastHit.getTime())),
      });
      sighting = element;
      await notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, element, user);
    }
    await addIndicatorHitsReportCount(args.count);
    return sighting;
  } finally {
    await lock.unlock();
  }
};

/**
 * Analyst action: ask the connector to deploy the indicator again.
 * The connector reconciliation re-pushes pending deployments.
 */
export const retryIndicatorDeployment = async (context: AuthContext, user: AuthUser, id: string) => {
  const relation = await loadDeployedOnById(context, user, id);
  const { element } = await patchAttribute(context, user, relation.internal_id, RELATION_DEPLOYED_ON, {
    deployment_status: DEPLOYMENT_STATUS_PENDING,
    error_message: null,
    revoked: false,
  });
  return notifyRelationEdit(user, element);
};

/**
 * Analyst action: withdraw the indicator from this platform only.
 * The relationship is revoked; the connector removes the indicator and reports removed,
 * otherwise the deployment manager flags it expired after the grace period.
 */
export const removeIndicatorDeployment = async (context: AuthContext, user: AuthUser, id: string) => {
  const relation = await loadDeployedOnById(context, user, id);
  const { element } = await patchAttribute(context, user, relation.internal_id, RELATION_DEPLOYED_ON, { revoked: true });
  return notifyRelationEdit(user, element);
};
// endregion

// region analytics
type FilterContent = { key: string[]; values: unknown[]; operator?: string; mode?: string };
const filterGroup = (filters: FilterContent[], filterGroups: unknown[] = [], mode: 'and' | 'or' = 'and') => ({ mode, filters, filterGroups }) as never;

const countIndicators = (context: AuthContext, user: AuthUser, filters: FilterContent[], groups: unknown[] = []) => {
  return elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { types: [ENTITY_TYPE_INDICATOR], filters: filterGroup(filters, groups) });
};

const countDeployments = (context: AuthContext, user: AuthUser, filters: FilterContent[]) => {
  return elCount(context, user, READ_INDEX_STIX_CORE_RELATIONSHIPS, { types: [RELATION_DEPLOYED_ON], filters: filterGroup(filters) });
};

const dateRangeFilters = (attribute: string, startDate?: DateInput, endDate?: DateInput): FilterContent[] => {
  const filters: FilterContent[] = [];
  if (startDate) filters.push({ key: [attribute], values: [new Date(startDate).toISOString()], operator: 'gte' });
  if (endDate) filters.push({ key: [attribute], values: [new Date(endDate).toISOString()], operator: 'lte' });
  return filters;
};

export const computeProvenShare = (live: number, proven: number) => (live > 0 ? Math.round((proven / live) * 1000) / 10 : 0);

export interface DisseminationAssuranceMetricsArgs {
  platformId?: string | null;
  startDate?: DateInput;
  endDate?: DateInput;
}

/**
 * Lifecycle funnel and proof metrics.
 * Without platform, stages count indicators (derived counters); with a platform, stages count its deployments.
 */
export const disseminationAssuranceMetrics = async (context: AuthContext, user: AuthUser, args: DisseminationAssuranceMetricsArgs) => {
  const now = new Date().toISOString();
  const platformFilters: FilterContent[] = args.platformId ? [{ key: ['toId'], values: [args.platformId] }] : [];
  const relationDates = dateRangeFilters('created_at', args.startDate, args.endDate);
  const baseDeploymentFilters = [...platformFilters, ...relationDates];
  const liveFilter: FilterContent = { key: ['deployment_status'], values: LIVE_DEPLOYMENT_STATUSES };
  const provenFilter: FilterContent = { key: ['validation_status'], values: PROVEN_VALIDATION_STATUSES };
  let funnel;
  if (args.platformId) {
    const [disseminated, deployed, validated, hit, expired] = await Promise.all([
      countDeployments(context, user, baseDeploymentFilters),
      countDeployments(context, user, [...baseDeploymentFilters, liveFilter]),
      countDeployments(context, user, [...baseDeploymentFilters, provenFilter]),
      countDeployments(context, user, [...baseDeploymentFilters, { key: ['hit_count'], values: [0], operator: 'gt' }]),
      countDeployments(context, user, [...baseDeploymentFilters, { key: ['deployment_status'], values: [DEPLOYMENT_STATUS_EXPIRED] }]),
    ]);
    funnel = { created: disseminated, disseminated, deployed, validated, hit, expired_still_deployed: expired };
  } else {
    const createdDates = dateRangeFilters('created_at', args.startDate, args.endDate);
    const isDeployed: FilterContent = { key: [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT], values: [0], operator: 'gt' };
    const disseminatedGroup = filterGroup([
      { key: ['x_opencti_detection'], values: [true] },
      isDeployed,
      { key: [INDICATOR_DEPLOYMENT_FAILED_COUNT], values: [0], operator: 'gt' },
    ], [], 'or');
    const expiredGroup = filterGroup([
      { key: ['revoked'], values: [true] },
      { key: ['valid_until'], values: [now], operator: 'lt' },
    ], [], 'or');
    const [created, disseminated, deployed, validated, hit, expired] = await Promise.all([
      countIndicators(context, user, createdDates),
      countIndicators(context, user, createdDates, [disseminatedGroup]),
      countIndicators(context, user, [...createdDates, isDeployed]),
      countIndicators(context, user, [...createdDates, { key: [INDICATOR_VALIDATED_PLATFORMS_COUNT], values: [0], operator: 'gt' }]),
      countIndicators(context, user, [...createdDates, { key: [INDICATOR_HIT_PLATFORMS_COUNT], values: [0], operator: 'gt' }]),
      countIndicators(context, user, [...createdDates, isDeployed], [expiredGroup]),
    ]);
    funnel = { created, disseminated, deployed, validated, hit, expired_still_deployed: expired };
  }
  const aggregate = async (field: string) => {
    const buckets = await elAggregationCount(context, user, READ_RELATIONSHIPS_INDICES, {
      types: [RELATION_DEPLOYED_ON],
      field,
      normalizeLabel: false,
      filters: filterGroup(baseDeploymentFilters),
    });
    return buckets
      .filter((bucket) => bucket.label !== 'unknown')
      .map((bucket) => ({ status: bucket.label, count: bucket.count }));
  };
  const byPlatform = async (filters: FilterContent[]) => {
    const distribution = await distributionRelations(context, user, {
      field: 'internal_id',
      relationship_type: [RELATION_DEPLOYED_ON],
      isTo: true,
      toTypes: [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM],
      limit: 10,
      filters: filterGroup([...baseDeploymentFilters, ...filters]),
    }) as unknown as Array<{ entity?: BasicStoreEntitySecurityPlatform | null; value: number }>;
    return distribution.filter((item) => item.entity).map((item) => ({ platform: item.entity as BasicStoreEntitySecurityPlatform, count: item.value }));
  };
  const [deploymentStatuses, validationStatuses, failuresByPlatform, deploymentsByPlatform, liveCount, provenLiveCount] = await Promise.all([
    aggregate('deployment_status'),
    aggregate('validation_status'),
    byPlatform([{ key: ['deployment_status'], values: [DEPLOYMENT_STATUS_FAILED] }]),
    byPlatform([liveFilter]),
    countDeployments(context, user, [...baseDeploymentFilters, liveFilter]),
    countDeployments(context, user, [...baseDeploymentFilters, liveFilter, provenFilter]),
  ]);
  return {
    funnel,
    deployment_statuses: deploymentStatuses,
    validation_statuses: validationStatuses,
    failures_by_platform: failuresByPlatform,
    deployments_by_platform: deploymentsByPlatform,
    proven_share: computeProvenShare(liveCount, provenLiveCount),
  };
};
// endregion

// region expiry interplay
/**
 * Indicators that expired or were revoked are removed by the connectors through the stream events they already consume
 * (revocation update, or delete event on filtered streams), and so are deployments withdrawn by an analyst (revoked relationship).
 * Live deployments without removal confirmation after the grace period are flagged expired:
 * a regular update, so history, stream and triggers ("expired but still deployed") see it.
 * updated_at is a conservative lower bound of the revocation time, heartbeats never change it.
 */
export const flagExpiredDeployments = async (context: AuthContext, user: AuthUser, gracePeriodMs: number, batchSize: number) => {
  const threshold = new Date(Date.now() - gracePeriodMs).toISOString();
  const liveFilter = { key: ['deployment_status'], values: LIVE_DEPLOYMENT_STATUSES };
  const expiredIndicators = await fullEntitiesList<BasicStoreEntityIndicator>(context, SYSTEM_USER, [ENTITY_TYPE_INDICATOR], {
    filters: {
      mode: 'and' as never,
      filters: [{ key: [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT], values: [0], operator: 'gt' as never }],
      filterGroups: [{
        mode: 'or' as never,
        filters: [{ key: ['valid_until'], values: [threshold], operator: 'lt' as never }],
        filterGroups: [{
          mode: 'and' as never,
          filters: [{ key: ['revoked'], values: [true] }, { key: ['updated_at'], values: [threshold], operator: 'lt' as never }],
          filterGroups: [],
        }],
      }],
    },
    noFiltersChecking: true,
    maxSize: batchSize,
  } as never);
  const fromExpiredIndicators = expiredIndicators.length === 0 ? [] : await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    fromId: expiredIndicators.map((i) => i.internal_id),
    filters: { mode: 'and' as never, filters: [liveFilter], filterGroups: [] },
    noFiltersChecking: true,
  });
  const withdrawn = await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    filters: {
      mode: 'and' as never,
      filters: [liveFilter, { key: ['revoked'], values: [true] }, { key: ['updated_at'], values: [threshold], operator: 'lt' as never }],
      filterGroups: [],
    },
    noFiltersChecking: true,
    maxSize: batchSize,
  } as never);
  const toFlag = new Map<string, BasicStoreRelationDeployedOn>();
  [...fromExpiredIndicators, ...withdrawn].forEach((relation) => toFlag.set(relation.internal_id, relation));
  let flagged = 0;
  await BluePromise.map([...toFlag.values()], async (relation) => {
    try {
      // A report can land between the scan and this write: recheck under the pair lock of the report path.
      // A relation changed since the scan is left to the next run, which sees its new state.
      const lock = await lockResources([pairLockKey(relation.fromId, relation.toId)]);
      try {
        const current = await findDeployedOn(context, SYSTEM_USER, relation.fromId, relation.toId);
        const unchanged = current && String(current.updated_at) === String(relation.updated_at);
        if (current && unchanged && LIVE_DEPLOYMENT_STATUSES.includes(current.deployment_status)) {
          const { element } = await patchAttribute(context, user, current.internal_id, RELATION_DEPLOYED_ON, { deployment_status: DEPLOYMENT_STATUS_EXPIRED });
          await notifyRelationEdit(user, element);
          flagged += 1;
        }
      } finally {
        await lock.unlock();
      }
    } catch (error) {
      logApp.error('[DISSEMINATION] Cannot flag deployment as expired', { cause: error, id: relation.internal_id });
    }
  }, { concurrency: BATCH_CONCURRENCY });
  if (flagged > 0) {
    await refreshIndicatorDeploymentCounters(context, [...toFlag.values()].map((r) => r.fromId));
    logApp.info('[DISSEMINATION] Deployments flagged as expired', { flagged });
  }
  return flagged;
};

/**
 * Safety net for counters: indicators of deployed-on relationships changed recently
 * (covers stream events missed while the manager was not running).
 */
export const repairRecentDeploymentCounters = async (context: AuthContext, sinceMs: number, batchSize: number) => {
  const since = new Date(Date.now() - sinceMs).toISOString();
  const relations = await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    filters: { mode: 'and' as never, filters: [{ key: ['updated_at'], values: [since], operator: 'gt' as never }], filterGroups: [] },
    noFiltersChecking: true,
    maxSize: batchSize,
  } as never);
  return refreshIndicatorDeploymentCounters(context, relations.map((r) => r.fromId));
};
// endregion

// region derived counters
const COUNTERS_BACKFILL_SOURCE = 'for (field in params.fields) { if (ctx._source[field] == null) { ctx._source[field] = 0; } }';
const COUNTER_FIELDS = [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT, INDICATOR_DEPLOYMENT_FAILED_COUNT, INDICATOR_VALIDATED_PLATFORMS_COUNT, INDICATOR_HIT_PLATFORMS_COUNT];

/**
 * Indicators created before dissemination assurance have no counters (new ones get 0 by default value).
 * They are backfilled with 0 in bounded batches by the deployment manager instead of a blocking startup migration.
 * Idempotent: only documents without the counter are touched, no stream event, no history.
 */
export const backfillIndicatorDeploymentCounters = async (batchSize: number) => {
  const result = await elRawUpdateByQuery({
    index: READ_INDEX_STIX_DOMAIN_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    max_docs: batchSize,
    body: {
      script: { source: COUNTERS_BACKFILL_SOURCE, lang: 'painless', params: { fields: COUNTER_FIELDS } },
      query: {
        bool: {
          must: [{ term: { 'entity_type.keyword': { value: ENTITY_TYPE_INDICATOR } } }],
          must_not: [{ exists: { field: INDICATOR_DEPLOYMENT_PLATFORMS_COUNT } }],
        },
      },
    },
  }) as { updated?: number };
  return result?.updated ?? 0;
};

/**
 * Recompute the derived deployment counters of the given indicators from their deployed-on relationships.
 * Runs as system user: only numbers are stored on the indicator, never the restricted relationships.
 * Side-channel update: no stream event, no history, updated_at kept.
 */
export const refreshIndicatorDeploymentCounters = async (context: AuthContext, indicatorIds: string[]) => {
  const uniqueIds = [...new Set(indicatorIds.filter((id) => isNotEmptyField(id)))];
  if (uniqueIds.length === 0) {
    return 0;
  }
  const indicators = await fullEntitiesList<BasicStoreEntityIndicator & Partial<IndicatorDeploymentCounters>>(context, SYSTEM_USER, [ENTITY_TYPE_INDICATOR], {
    filters: { mode: 'and' as never, filters: [{ key: ['internal_id'], values: uniqueIds }], filterGroups: [] },
    noFiltersChecking: true,
  });
  if (indicators.length === 0) {
    return 0;
  }
  const relations = await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    fromId: indicators.map((i) => i.internal_id),
  });
  const relationsByIndicator = new Map<string, BasicStoreRelationDeployedOn[]>();
  relations.forEach((relation) => {
    const list = relationsByIndicator.get(relation.fromId) ?? [];
    list.push(relation);
    relationsByIndicator.set(relation.fromId, list);
  });
  let updated = 0;
  await BluePromise.map(indicators, async (indicator) => {
    const counters = computeIndicatorDeploymentCounters(relationsByIndicator.get(indicator.internal_id) ?? []);
    const unchanged = (Object.keys(counters) as Array<keyof IndicatorDeploymentCounters>)
      .every((key) => (indicator[key] ?? 0) === counters[key] && indicator[key] !== undefined);
    if (!unchanged) {
      const params = buildReplaceScriptParams(counters);
      await elUpdate(context, indicator._index, indicator.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
      updated += 1;
    }
  }, { concurrency: BATCH_CONCURRENCY });
  return updated;
};
// endregion
