import { Promise as BluePromise } from 'bluebird';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { createRelation, distributionRelations, patchAttribute, patchAttributeFromLoadedWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import {
  fullEntitiesList,
  fullRelationsList,
  internalFindByIds,
  internalLoadById,
  pageEntitiesConnection,
  pageRegardingEntitiesConnection,
  pageRelationsConnection,
  storeLoadById,
  storeLoadByIds,
  topRelationsList,
} from '../../database/middleware-loader';
import { buildReplaceScriptParams, EL_REPLACE_SCRIPT_SOURCE, elAggregationCount, elCount, elRawUpdateByQuery, elUpdate } from '../../database/engine';
import {
  isEmptyField,
  isNotEmptyField,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_RELATIONSHIPS_INDICES,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REPLACE,
} from '../../database/utils';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { BasicStoreSettings } from '../../types/settings';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { lockResources } from '../../lock/master-lock';
import { notify, redisGetManagerEventState, redisSetManagerEventState } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError, ValidationError } from '../../config/errors';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_INDICATOR, type BasicStoreEntityIndicator } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_IOC_VALIDATION_REQUEST } from '../iocValidation/iocValidation-types';
import { EXPIRATION_MANAGER_USER, INTERNAL_USERS, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { isEnterpriseEditionFromSettings } from '../../enterprise-edition/ee';
import { storeUpdateEvent } from '../../database/stream/stream-handler';
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
  INDICATOR_DEPLOYMENT_EXPIRED_COUNT,
  INDICATOR_DEPLOYMENT_FAILED_COUNT,
  INDICATOR_DEPLOYMENT_PLATFORMS_COUNT,
  INDICATOR_DEPLOYMENTS_COUNT,
  INDICATOR_HIT_PLATFORMS_COUNT,
  INDICATOR_VALIDATED_PLATFORMS_COUNT,
  type IndicatorDeploymentCounters,
  LIVE_DEPLOYMENT_STATUSES,
  PROVEN_VALIDATION_STATUSES,
  RELATION_DEPLOYED_ON,
  type StoreRelationDeployedOn,
} from './indicatorDeployment-types';
import {
  hitsSightingStixId,
  isDeploymentStatus,
  isPairReadableByReporter,
  isReadableWithIndicator,
  pairMarkings,
  pairOrganizations,
  validationResultSightingStixId,
} from './indicatorDeployment-utils';
import { sightingReportContext } from './indicatorDeployment-sightings';
import { consumeDeploymentRateLimit, DEPLOYMENT_RATE_LIMIT_BATCH, DEPLOYMENT_RATE_LIMIT_HITS, DEPLOYMENT_RATE_LIMIT_SINGLE } from './indicatorDeployment-rate-limit';

export const DEPLOYMENT_BATCH_MAX_SIZE = 500;
const EXTERNAL_ID_MAX_LENGTH = 1000;
const ERROR_MESSAGE_MAX_LENGTH = 5000;
const BATCH_CONCURRENCY = 5;

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
  // Attributes to write. Always contains last_sync_at, except for a stale report (nothing to write).
  attributes: Partial<Record<keyof DeployedOnAttributes, unknown>>;
  // True when the change must go through the regular update path (history, stream event, triggers).
  meaningful: boolean;
  // True when the report was synchronized before the last applied one: the platform already left that state.
  stale: boolean;
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

const RETRYABLE_DEPLOYMENT_STATUSES: DeploymentStatus[] = [DEPLOYMENT_STATUS_FAILED, DEPLOYMENT_STATUS_REMOVED, DEPLOYMENT_STATUS_EXPIRED];
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
  const reportedSyncAt = toDate(report.syncedAt, now);
  // A sync time ahead of the platform clock would make every later report look stale.
  const syncedAt = reportedSyncAt.getTime() > now.getTime() ? now : reportedSyncAt;
  if (current && isNotEmptyField(current.last_sync_at) && syncedAt.getTime() < toDate(current.last_sync_at, syncedAt).getTime()) {
    // Reports of one pair are serialized in arrival order only: a delayed snapshot never rolls the lifecycle back.
    return { attributes: {}, meaningful: false, stale: true };
  }
  const status = resolveEffectiveStatus(current?.deployment_status, report.status);
  const errorMessage = status === DEPLOYMENT_STATUS_FAILED && isNotEmptyField(report.errorMessage) ? report.errorMessage : null;
  if (!current) {
    const attributes: DeploymentChange['attributes'] = { deployment_status: status, last_sync_at: syncedAt };
    if (isNotEmptyField(report.externalId)) attributes.external_id = report.externalId;
    if (isLive(status)) attributes.deployed_at = toDate(report.deployedAt, now);
    if (status === DEPLOYMENT_STATUS_REMOVED) attributes.removed_at = toDate(report.removedAt, now);
    if (errorMessage) attributes.error_message = errorMessage;
    return { attributes, meaningful: true, stale: false };
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
  return { attributes: { ...patch, last_sync_at: syncedAt }, meaningful, stale: false };
};

// A deployment is disseminated once a connector reported it: only lifecycle writers set last_sync_at, so the pending
// record an editor creates is not counted until its connector reports it.
export const isReportedDeployment = (relation: Partial<DeployedOnAttributes>) => isNotEmptyField(relation.last_sync_at);

export const computeIndicatorDeploymentCounters = (relations: Array<Partial<DeployedOnAttributes>>): IndicatorDeploymentCounters => {
  return {
    [INDICATOR_DEPLOYMENTS_COUNT]: relations.filter(isReportedDeployment).length,
    [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT]: relations.filter((r) => isLive(r.deployment_status)).length,
    [INDICATOR_DEPLOYMENT_FAILED_COUNT]: relations.filter((r) => r.deployment_status === DEPLOYMENT_STATUS_FAILED).length,
    [INDICATOR_DEPLOYMENT_EXPIRED_COUNT]: relations.filter((r) => r.deployment_status === DEPLOYMENT_STATUS_EXPIRED).length,
    [INDICATOR_VALIDATED_PLATFORMS_COUNT]: relations.filter((r) => PROVEN_VALIDATION_STATUSES.includes(r.validation_status as never)).length,
    [INDICATOR_HIT_PLATFORMS_COUNT]: relations.filter((r) => (r.hit_count ?? 0) > 0).length,
  };
};

export type HitsDeploymentState = Partial<Pick<DeployedOnAttributes, 'hit_count' | 'first_hit_at' | 'last_hit_at'>>;
export interface HitsSightingState {
  attribute_count?: number | null;
  first_seen?: DateInput;
  last_seen?: DateInput;
}
export interface HitsSightingValues {
  attribute_count: number;
  first_seen: Date;
  last_seen: Date;
}

// The hit counts are 32-bit integers (mapping and API): they stop at the largest one instead of failing the report,
// so the replay watermark and the sighting keep moving once it is reached.
export const HIT_COUNT_MAX = 2147483647;

export const addHits = (count: number, newHits: number) => Math.min(HIT_COUNT_MAX, count + newHits);

/**
 * Values of the hits sighting, rebuilt from the deployment (the durable record of the hits) so that a sighting
 * left behind by a failed write is repaired: the count never goes below the deployment hit count and never
 * decreases, the dates only widen. `newHits` are the hits of the current report (0 for a replay, already counted).
 */
export const computeHitsSightingValues = (
  sighting: HitsSightingState | undefined,
  deployment: HitsDeploymentState,
  newHits: number,
  reportFirstHit: Date,
  reportLastHit: Date,
): HitsSightingValues => {
  const deploymentCount = deployment.hit_count ?? 0;
  const firstHit = toDate(deployment.first_hit_at, reportFirstHit);
  const lastHit = toDate(deployment.last_hit_at, reportLastHit);
  if (!sighting) {
    return { attribute_count: addHits(0, Math.max(deploymentCount, newHits)), first_seen: firstHit, last_seen: lastHit };
  }
  const sightingFirst = toDate(sighting.first_seen, firstHit);
  const sightingLast = toDate(sighting.last_seen, lastHit);
  return {
    attribute_count: Math.max(addHits(sighting.attribute_count ?? 0, newHits), Math.min(deploymentCount, HIT_COUNT_MAX)),
    first_seen: sightingFirst.getTime() <= firstHit.getTime() ? sightingFirst : firstHit,
    last_seen: sightingLast.getTime() >= lastHit.getTime() ? sightingLast : lastHit,
  };
};

export const HIT_REPORT_IDS_MAX = 100;
export const HIT_REPORT_ID_MAX_LENGTH = 256;
// Clock skew tolerated between a security platform and the platform on the time of the last hit of a report.
export const HIT_TIME_MAX_AHEAD_MS = 5 * 60 * 1000;
type HitsReplayState = Partial<Pick<DeployedOnAttributes, 'last_hit_at' | 'last_hit_report_ids'>>;

/**
 * Whether a hits report was already counted. The last hit is the watermark: a report ending before the last known
 * hit is a replay, one ending after it is new. Reports ending at the last known hit are told apart by their report
 * id: the ids counted at that instant are kept, so a retry is a replay and another report is counted.
 */
export const isHitsReplay = (deployment: HitsReplayState | undefined, lastHit: Date, reportId?: string | null) => {
  if (!deployment || isEmptyField(deployment.last_hit_at)) {
    return false;
  }
  const lastKnownHit = toDate(deployment.last_hit_at, lastHit).getTime();
  if (lastHit.getTime() !== lastKnownHit) {
    return lastHit.getTime() < lastKnownHit;
  }
  return isEmptyField(reportId) || (deployment.last_hit_report_ids ?? []).includes(reportId as string);
};

/**
 * The report ids counted at the last hit once a report is counted (only called for a report that is not a replay,
 * before any count changes). An id is never evicted while its instant is the watermark, or its retry would be counted
 * again: a report beyond the limit at the same instant is refused instead.
 */
export const hitReportIdsAfter = (deployment: HitsReplayState | undefined, lastHit: Date, reportId?: string | null) => {
  const sameInstant = !!deployment && isNotEmptyField(deployment.last_hit_at)
    && toDate(deployment.last_hit_at, lastHit).getTime() === lastHit.getTime();
  const kept = sameInstant ? (deployment?.last_hit_report_ids ?? []) : [];
  if (isEmptyField(reportId)) {
    return kept;
  }
  if (kept.length >= HIT_REPORT_IDS_MAX) {
    throw ValidationError(`At most ${HIT_REPORT_IDS_MAX} distinct hit reports can end at the same instant`, 'reportId', {
      last_hit: lastHit.toISOString(),
    });
  }
  return [...kept, reportId as string];
};

export const isHitsSightingUpToDate = (sighting: HitsSightingState, values: HitsSightingValues) => {
  const sameTime = (current: DateInput, expected: Date) => isNotEmptyField(current) && toDate(current, expected).getTime() === expected.getTime();
  return (sighting.attribute_count ?? 0) === values.attribute_count
    && sameTime(sighting.first_seen, values.first_seen)
    && sameTime(sighting.last_seen, values.last_seen);
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

/** Whether an accepted report adds its account to the creators of the deployment (internal and no-creator accounts never are). */
const isNewDeploymentReporter = (deployment: { creator_id?: string | string[] | null }, user: AuthUser) => {
  if (INTERNAL_USERS[user.id] || user.no_creators) {
    return false;
  }
  const creators = Array.isArray(deployment.creator_id) ? deployment.creator_id : [deployment.creator_id];
  return !creators.includes(user.id);
};

const notifyRelationEdit = async (user: AuthUser, element: unknown) => {
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, element, user);
};

type ReportOutcome = 'created' | 'updated' | 'unchanged';

/**
 * Markings of a pair relationship (deployment, hits sighting, validation result sighting): its own markings and those of
 * its indicator and of its security platform, the highest of each type kept. An end that gets or raises a marking is
 * followed at once; a marking stricter than the ends is kept, since a marking set on the relationship on purpose
 * cannot be told from one an end has since relaxed (an editor can lower it to the level of the ends).
 */
export const expectedPairMarkings = async (
  context: AuthContext,
  current: string[],
  indicator: { [RELATION_OBJECT_MARKING]?: string[] | null },
  platform: { [RELATION_OBJECT_MARKING]?: string[] | null },
) => {
  const cleaned = await cleanMarkings(context, [...current, ...pairMarkings(indicator, platform)]);
  return [...new Set(cleaned
    .map((marking: { internal_id?: string } | string) => (typeof marking === 'string' ? marking : marking.internal_id))
    .filter((id: string | undefined): id is string => !!id))];
};

const ensurePairMarkings = async (
  context: AuthContext,
  user: AuthUser,
  relation: { internal_id: string; entity_type: string; [RELATION_OBJECT_MARKING]?: string[] | null },
  indicator: BasicStoreEntityIndicator,
  platform: BasicStoreEntitySecurityPlatform,
) => {
  const current = relation[RELATION_OBJECT_MARKING] ?? [];
  const expected = await expectedPairMarkings(context, current, indicator, platform);
  if (current.length !== expected.length || expected.some((id) => !current.includes(id))) {
    await patchAttribute(context, user, relation.internal_id, relation.entity_type, { [INPUT_MARKINGS]: expected }, {
      operations: { [INPUT_MARKINGS]: UPDATE_OPERATION_REPLACE },
    });
  }
};

/**
 * Organizations a new pair relationship is shared with (see pairOrganizations). The reporting account maintains the
 * relationship and must find it again on its next report, so a pair it would not read is refused: its indicator and
 * its security platform need a common organization of the account.
 */
const pairSharingForReporter = async (
  context: AuthContext,
  user: AuthUser,
  indicator: BasicStoreEntityIndicator,
  platform: BasicStoreEntitySecurityPlatform,
) => {
  const organizations = pairOrganizations(indicator, platform);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const reporter = {
    insidePlatformOrganization: isUserInPlatformOrganization(user, settings),
    organizationIds: (user.organizations ?? []).map((organization) => organization.internal_id),
  };
  if (!isPairReadableByReporter(organizations, reporter)) {
    throw FunctionalError('The indicator and the security platform are not shared with a common organization of the reporting account', {
      indicatorId: indicator.internal_id,
      platformId: platform.internal_id,
    });
  }
  return organizations;
};

/**
 * A pair relationship shared with other organizations than those both its ends are shared with (an end was shared or
 * unshared since) gets their common organizations instead.
 */
const ensurePairOrganizations = async (
  context: AuthContext,
  user: AuthUser,
  relation: { internal_id: string; entity_type: string; [RELATION_GRANTED_TO]?: string[] | null },
  indicator: BasicStoreEntityIndicator,
  platform: BasicStoreEntitySecurityPlatform,
) => {
  const current = relation[RELATION_GRANTED_TO] ?? [];
  const expected = pairOrganizations(indicator, platform);
  if (current.length !== expected.length || expected.some((organization) => !current.includes(organization))) {
    await patchAttribute(context, user, relation.internal_id, relation.entity_type, { [INPUT_GRANTED_REFS]: expected }, {
      operations: { [INPUT_GRANTED_REFS]: UPDATE_OPERATION_REPLACE },
    });
  }
};

/**
 * A pair relationship is created with the access of the ends read before its creation. An end restricted meanwhile
 * is repaired from its change event, which only finds the relationships existing by then: once the relationship
 * exists, its ends are read again and its access repaired as that event would, so either one sees the change.
 */
export const ensureCreatedPairAccess = async (
  context: AuthContext,
  created: { internal_id: string; entity_type: string },
  indicatorId: string,
  platformId: string,
) => {
  const [relation, indicator, platform] = await Promise.all([
    storeLoadById<BasicStoreRelation>(context, SYSTEM_USER, created.internal_id, created.entity_type),
    storeLoadById<BasicStoreEntityIndicator>(context, SYSTEM_USER, indicatorId, ENTITY_TYPE_INDICATOR),
    storeLoadById<BasicStoreEntitySecurityPlatform>(context, SYSTEM_USER, platformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM),
  ]);
  if (!relation || !indicator || !platform) {
    return;
  }
  await ensurePairMarkings(context, EXPIRATION_MANAGER_USER, relation, indicator, platform);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  if (isEnterpriseEditionFromSettings(settings)) {
    await ensurePairOrganizations(context, EXPIRATION_MANAGER_USER, relation, indicator, platform);
  }
};

// Serializes every write on one (indicator, platform) pair. Never an entity id: createRelation locks the ids
// of the elements it writes, and locking one of them here would make the nested creation wait on this lock.
export const pairLockKey = (indicatorInternalId: string, platformInternalId: string) => `deployed-on-${indicatorInternalId}-${platformInternalId}`;

// The deployments of the changed endpoints are repaired one page at a time, with every lookup of a page batched.
const PAIR_REPAIR_PAGE_SIZE = 500;
const PAIR_REQUESTS_PAGE_SIZE = 500;
const SIGHTINGS_LOAD_CHUNK_SIZE = 500;
const pairKey = (indicatorId: string, platformId: string) => `${indicatorId}|${platformId}`;

type RepairPair = { deployment: BasicStoreRelationDeployedOn; indicator: BasicStoreEntityIndicator; platform: BasicStoreEntitySecurityPlatform };

// Sightings of the pairs of a page, loaded in chunks: hits sightings and validation result sightings alike.
const forEachPairSighting = async (
  context: AuthContext,
  sightingIds: string[],
  callback: (sighting: BasicStoreRelation) => Promise<void>,
) => {
  for (let index = 0; index < sightingIds.length; index += SIGHTINGS_LOAD_CHUNK_SIZE) {
    const chunk = sightingIds.slice(index, index + SIGHTINGS_LOAD_CHUNK_SIZE);
    const sightings = await internalFindByIds<BasicStoreRelation>(context, SYSTEM_USER, chunk, { type: STIX_SIGHTING_RELATIONSHIP }) as BasicStoreRelation[];
    await BluePromise.map(sightings.filter((sighting) => sighting), callback, { concurrency: BATCH_CONCURRENCY });
  }
};

// Validation requests that included pairs of a page, read one page of requests at a time: the result sightings they may
// have written for these pairs. A deleted request takes its result sightings with it.
const forEachPageValidationRequests = async (
  context: AuthContext,
  pairs: RepairPair[],
  callback: (sightingIds: string[]) => Promise<void>,
) => {
  const indicatorIds = [...new Set(pairs.map((pair) => pair.indicator.internal_id))];
  const platformIds = [...new Set(pairs.map((pair) => pair.platform.internal_id))];
  await fullEntitiesList<BasicStoreEntity & { indicator_ids?: string[]; platform_ids?: string[] }>(context, SYSTEM_USER, [ENTITY_TYPE_IOC_VALIDATION_REQUEST], {
    filters: { mode: 'and', filters: [{ key: ['indicator_ids'], values: indicatorIds }, { key: ['platform_ids'], values: platformIds }], filterGroups: [] },
    noFiltersChecking: true,
    baseData: true,
    baseFields: ['indicator_ids', 'platform_ids'],
    first: PAIR_REQUESTS_PAGE_SIZE,
    callback: async (requests: Array<BasicStoreEntity & { indicator_ids?: string[]; platform_ids?: string[] }>) => {
      const sightingIds = requests.flatMap((request) => pairs
        .filter((pair) => (request.indicator_ids ?? []).includes(pair.indicator.internal_id) && (request.platform_ids ?? []).includes(pair.platform.internal_id))
        .map((pair) => validationResultSightingStixId(request.internal_id, pair.indicator.internal_id, pair.platform.internal_id)));
      await callback(sightingIds);
      return true;
    },
  } as never);
};

/**
 * After a marking or sharing change of indicators or security platforms, the deployments of their pairs, the hits
 * sightings and the validation result sightings of every request that included the pair take the markings of both ends
 * (see expectedPairMarkings) and the organizations both ends are now shared with, and the counters of the indicators
 * are recomputed. Sharing is only repaired with the Enterprise Edition, without which it never changes nor restricts
 * reads. Memory is bounded by one page: PAIR_REPAIR_PAGE_SIZE deployments, their ends and their sightings loaded in
 * batches, the requests of the page read PAIR_REQUESTS_PAGE_SIZE at a time.
 */
export const repairPairMarkings = async (context: AuthContext, user: AuthUser, changes: { indicatorIds: string[]; platformIds: string[] }) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const repairSharing = isEnterpriseEditionFromSettings(settings);
  const ensurePairAccess = async (relation: BasicStoreRelation, pair: RepairPair) => {
    await ensurePairMarkings(context, user, relation, pair.indicator, pair.platform);
    if (repairSharing) {
      await ensurePairOrganizations(context, user, relation, pair.indicator, pair.platform);
    }
  };
  const changedIndicatorIds = new Set(changes.indicatorIds);
  let repaired = 0;
  const repairPage = async (page: BasicStoreRelationDeployedOn[]) => {
    const endpointIds = [...new Set(page.flatMap((deployment) => [deployment.fromId, deployment.toId]))];
    const endpoints = await storeLoadByIds<BasicStoreEntityIndicator | BasicStoreEntitySecurityPlatform>(context, SYSTEM_USER, endpointIds, ABSTRACT_STIX_DOMAIN_OBJECT);
    const endpointsById = new Map(endpoints.filter((endpoint) => endpoint).map((endpoint) => [endpoint.internal_id, endpoint]));
    const pairs = page.map((deployment) => ({
      deployment,
      indicator: endpointsById.get(deployment.fromId) as BasicStoreEntityIndicator | undefined,
      platform: endpointsById.get(deployment.toId) as BasicStoreEntitySecurityPlatform | undefined,
    })).filter((pair): pair is RepairPair => !!pair.indicator && !!pair.platform);
    if (pairs.length === 0) {
      return;
    }
    const pairsByKey = new Map(pairs.map((pair) => [pairKey(pair.indicator.internal_id, pair.platform.internal_id), pair]));
    const repairSighting = async (sighting: BasicStoreRelation) => {
      const pair = pairsByKey.get(pairKey(sighting.fromId, sighting.toId));
      if (pair) {
        await ensurePairAccess(sighting, pair);
      }
    };
    await BluePromise.map(pairs, (pair) => ensurePairAccess(pair.deployment, pair), { concurrency: BATCH_CONCURRENCY });
    await forEachPairSighting(context, pairs.map((pair) => hitsSightingStixId(pair.indicator.internal_id, pair.platform.internal_id)), repairSighting);
    await forEachPageValidationRequests(context, pairs, (sightingIds) => forEachPairSighting(context, sightingIds, repairSighting));
    await refreshIndicatorDeploymentCounters(context, [...new Set(pairs.map((pair) => pair.indicator.internal_id))]);
    repaired += pairs.length;
  };
  const listOpts = { first: PAIR_REPAIR_PAGE_SIZE, callback: async (page: BasicStoreRelationDeployedOn[]) => {
    await repairPage(page);
    return true;
  } };
  if (changes.indicatorIds.length > 0) {
    await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, { ...listOpts, fromId: changes.indicatorIds } as never);
  }
  if (changes.platformIds.length > 0) {
    // A deployment whose indicator changed too was repaired with the indicators
    await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
      ...listOpts,
      toId: changes.platformIds,
      callback: async (page: BasicStoreRelationDeployedOn[]) => {
        await repairPage(page.filter((deployment) => !changedIndicatorIds.has(deployment.fromId)));
        return true;
      },
    } as never);
  }
  return repaired;
};

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
    if (existing) {
      await ensurePairMarkings(context, user, existing, indicator, platform);
    }
    const change = computeDeploymentChange(existing, report, now);
    if (!existing) {
      const element = await createRelation(context, user, {
        fromId: indicator.internal_id,
        toId: platform.internal_id,
        relationship_type: RELATION_DEPLOYED_ON,
        [INPUT_MARKINGS]: pairMarkings(indicator, platform),
        [INPUT_GRANTED_REFS]: await pairSharingForReporter(context, user, indicator, platform),
        ...change.attributes,
      }, { grantedRefsFromInput: true }) as unknown as BasicStoreRelationDeployedOn;
      await ensureCreatedPairAccess(context, element, indicator.internal_id, platform.internal_id);
      return { element, outcome: 'created' };
    }
    if (change.stale) {
      return { element: existing, outcome: 'unchanged' };
    }
    // An accepted report makes its account a reporter of the deployment, as an upsert would: its later
    // validation results are trusted (isTrustedDeploymentReporter reads creator_id)
    const addsReporter = isNewDeploymentReporter(existing, user);
    // The first report makes the deployment count as disseminated: it takes the regular path, whose
    // event refreshes the indicator counters, and only a deployment already reported gets a heartbeat
    if (!change.meaningful && !addsReporter && isReportedDeployment(existing)) {
      await touchLastSync(context, existing, change.attributes.last_sync_at);
      return { element: { ...existing, last_sync_at: change.attributes.last_sync_at as Date }, outcome: 'unchanged' };
    }
    const patch: Record<string, unknown> = addsReporter ? { ...change.attributes, creator_id: [user.id] } : change.attributes;
    const { element } = await patchAttribute(context, user, existing.internal_id, RELATION_DEPLOYED_ON, patch, {
      operations: addsReporter ? { creator_id: UPDATE_OPERATION_ADD } : undefined,
    });
    await notifyRelationEdit(user, element);
    return { element: element as unknown as BasicStoreRelationDeployedOn, outcome: change.meaningful ? 'updated' : 'unchanged' };
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
  const recordError = (input: IndicatorDeploymentReportInput, error: unknown) => {
    const message = (error as { message?: string }).message ?? 'Unknown error';
    result.errors.push({ indicatorId: input.indicatorId, message });
  };
  const resolved = await BluePromise.map(reports, async (input) => {
    try {
      const report = toReport(input.status, input.externalId, input.metadata);
      computeDeploymentChange(undefined, report, new Date());
      const indicator = await loadIndicator(context, user, input.indicatorId);
      return { input, report, indicator };
    } catch (error) {
      recordError(input, error);
      return undefined;
    }
  }, { concurrency: BATCH_CONCURRENCY });
  // The reports of one indicator, whatever ids name it, are applied in the batch order, as separate calls would be
  const byIndicator = new Map<string, Array<NonNullable<typeof resolved[number]>>>();
  resolved.forEach((entry) => {
    if (entry) {
      byIndicator.set(entry.indicator.internal_id, [...(byIndicator.get(entry.indicator.internal_id) ?? []), entry]);
    }
  });
  await BluePromise.map([...byIndicator.values()], (entries) => BluePromise.mapSeries(entries, async ({ input, report, indicator }) => {
    try {
      const { outcome } = await applyDeploymentReport(context, user, indicator, platform, report);
      result.processed += 1;
      result[outcome] += 1;
    } catch (error) {
      recordError(input, error);
    }
  }), { concurrency: BATCH_CONCURRENCY });
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
  // Required replay watermark: a report whose last hit is not after the last known hit is already counted.
  lastHit?: DateInput;
  firstHit?: DateInput;
  reportId?: string | null;
}

export const reportIndicatorHits = async (context: AuthContext, user: AuthUser, args: ReportHitsArgs) => {
  await consumeDeploymentRateLimit(DEPLOYMENT_RATE_LIMIT_HITS, user);
  if (!Number.isInteger(args.count) || args.count < 1) {
    throw ValidationError('Hit count must be a positive integer', 'count', { count: args.count });
  }
  if (isEmptyField(args.lastHit)) {
    throw ValidationError('The time of the last hit is required: it keeps a retried report from being counted twice', 'lastHit');
  }
  if (isNotEmptyField(args.reportId) && (args.reportId as string).length > HIT_REPORT_ID_MAX_LENGTH) {
    throw ValidationError(`A report id cannot exceed ${HIT_REPORT_ID_MAX_LENGTH} characters`, 'reportId');
  }
  const now = new Date();
  const lastHit = toDate(args.lastHit, now);
  const firstHit = toDate(args.firstHit, lastHit);
  if (firstHit.getTime() > lastHit.getTime()) {
    throw ValidationError('First hit cannot be after last hit', 'firstHit');
  }
  // Refused rather than clamped: a future watermark would count every later report ending before it as a replay
  if (lastHit.getTime() > now.getTime() + HIT_TIME_MAX_AHEAD_MS) {
    throw ValidationError(
      `The time of the last hit cannot be more than ${HIT_TIME_MAX_AHEAD_MS / 60000} minutes ahead of the platform clock`,
      'lastHit',
      { last_hit: lastHit.toISOString() },
    );
  }
  const [indicator, platform] = await Promise.all([
    loadIndicator(context, user, args.indicatorId),
    loadSecurityPlatform(context, user, args.platformId),
  ]);
  const sightingStixId = hitsSightingStixId(indicator.internal_id, platform.internal_id);
  const lock = await lockResources([pairLockKey(indicator.internal_id, platform.internal_id)]);
  try {
    const existing = await findDeployedOn(context, user, indicator.internal_id, platform.internal_id);
    const existingSighting = await internalLoadById<BasicStoreRelation & {
      attribute_count?: number;
      first_seen?: string;
      last_seen?: string;
      x_opencti_negative?: boolean;
    }>(
      context,
      user,
      sightingStixId,
      { type: STIX_SIGHTING_RELATIONSHIP },
    );
    // Only the positive sighting of this very pair records its hits: anything else holding the id is left untouched.
    if (existingSighting && (existingSighting.fromId !== indicator.internal_id || existingSighting.toId !== platform.internal_id
      || existingSighting.x_opencti_negative === true)) {
      throw FunctionalError('The hits sighting identifier of this indicator and security platform is held by another sighting', {
        indicator_id: indicator.internal_id,
        platform_id: platform.internal_id,
        sighting_id: existingSighting.internal_id,
      });
    }
    if (existing) {
      await ensurePairMarkings(context, user, existing, indicator, platform);
    }
    if (existingSighting) {
      await ensurePairMarkings(context, user, existingSighting, indicator, platform);
    }
    const reportContext = sightingReportContext(context);
    // The reserved id is the standard id too: a standard id derived from the pair and the seen dates would be the one
    // of an ordinary sighting of the pair seen at the same instants
    const createHitsSighting = async (count: number, firstSeen: Date, lastSeen: Date) => createRelation(reportContext, user, {
      fromId: indicator.internal_id,
      toId: platform.internal_id,
      relationship_type: STIX_SIGHTING_RELATIONSHIP,
      standard_id: sightingStixId,
      stix_id: sightingStixId,
      [INPUT_MARKINGS]: pairMarkings(indicator, platform),
      [INPUT_GRANTED_REFS]: await pairSharingForReporter(context, user, indicator, platform),
      attribute_count: count,
      first_seen: firstSeen,
      last_seen: lastSeen,
      x_opencti_negative: false,
      description: `Hits reported by the ${platform.name} integration`,
    }, { grantedRefsFromInput: true });
    // Replay of an already counted report: the hits are never counted twice.
    const replay = isHitsReplay(existing, lastHit, args.reportId);
    const reportIds = replay ? undefined : hitReportIdsAfter(existing, lastHit, args.reportId);
    let deployment: HitsDeploymentState | undefined = existing;
    // 01. Deployment state, the durable record of the hits: hits prove the indicator is live on the platform
    if (!existing) {
      deployment = await createRelation(context, user, {
        fromId: indicator.internal_id,
        toId: platform.internal_id,
        relationship_type: RELATION_DEPLOYED_ON,
        [INPUT_MARKINGS]: pairMarkings(indicator, platform),
        [INPUT_GRANTED_REFS]: await pairSharingForReporter(context, user, indicator, platform),
        deployment_status: DEPLOYMENT_STATUS_ACTIVE,
        deployed_at: firstHit,
        last_sync_at: now,
        hit_count: args.count,
        first_hit_at: firstHit,
        last_hit_at: lastHit,
        last_hit_report_ids: reportIds,
      }, { grantedRefsFromInput: true }) as unknown as HitsDeploymentState;
      await ensureCreatedPairAccess(context, deployment as unknown as BasicStoreRelationDeployedOn, indicator.internal_id, platform.internal_id);
    } else if (!replay) {
      const patch: Record<string, unknown> = {
        hit_count: addHits(existing.hit_count ?? 0, args.count),
        last_hit_at: lastHit,
        last_hit_report_ids: reportIds,
        last_sync_at: now,
      };
      if (isEmptyField(existing.first_hit_at) || firstHit.getTime() < new Date(existing.first_hit_at as Date | string).getTime()) {
        patch.first_hit_at = firstHit;
      }
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
      deployment = element as unknown as HitsDeploymentState;
    }
    // 02. Stable hits sighting Indicator -> Security Platform, always rebuilt from the deployment: the deployment
    // is written first, so a retry after a failed sighting write (a replay) repairs the sighting.
    const values = computeHitsSightingValues(existingSighting, deployment ?? {}, replay ? 0 : args.count, firstHit, lastHit);
    let sighting;
    if (!existingSighting) {
      sighting = await createHitsSighting(values.attribute_count, values.first_seen, values.last_seen);
      await ensureCreatedPairAccess(context, sighting as unknown as BasicStoreRelation, indicator.internal_id, platform.internal_id);
    } else if (!isHitsSightingUpToDate(existingSighting, values)) {
      const { element } = await patchAttribute(reportContext, user, existingSighting.internal_id, STIX_SIGHTING_RELATIONSHIP, values);
      sighting = element;
      await notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, element, user);
    } else {
      sighting = existingSighting;
    }
    if (!replay) {
      await addIndicatorHitsReportCount(args.count);
    }
    return sighting;
  } finally {
    await lock.unlock();
  }
};

/**
 * Records (or clears, with null) the start of the removal grace period of a deployment: bookkeeping of the expiry rules,
 * written without stream event, history or change of updated_at, so no edit of the deployment ever moves it.
 */
const setRemovalRequestedAt = async (context: AuthContext, relation: { _index: string; internal_id: string }, at: Date | null) => {
  const params = buildReplaceScriptParams({ removal_requested_at: at });
  await elUpdate(context, relation._index, relation.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
};

/**
 * Analyst action: ask the connector to deploy the indicator again.
 * The connector reconciliation re-pushes pending deployments.
 */
export const retryIndicatorDeployment = async (context: AuthContext, user: AuthUser, id: string) => {
  const relation = await loadDeployedOnById(context, user, id);
  // Checked under the pair lock of the connector reports: a deployment confirmed meanwhile is never reset.
  const lock = await lockResources([pairLockKey(relation.fromId, relation.toId)]);
  try {
    const current = await storeLoadByIdWithRefs<StoreRelationDeployedOn>(context, user, id, { type: RELATION_DEPLOYED_ON });
    if (!current) {
      throw FunctionalError('Deployment not found or not accessible', { id });
    }
    if (!RETRYABLE_DEPLOYMENT_STATUSES.includes(current.deployment_status as DeploymentStatus)) {
      throw FunctionalError('Only a failed, removed or expired deployment can be retried', { id, status: current.deployment_status });
    }
    // Lifecycle fields are refused to a regular edition (deployed-on validator): this action, checked above, writes its reset directly.
    const { element } = await patchAttributeFromLoadedWithRefs(context, user, current, {
      deployment_status: DEPLOYMENT_STATUS_PENDING,
      error_message: null,
      revoked: false,
    });
    if (isNotEmptyField(current.removal_requested_at)) {
      await setRemovalRequestedAt(context, current, null);
    }
    return await notifyRelationEdit(user, element);
  } finally {
    await lock.unlock();
  }
};

/**
 * Analyst action: withdraw the indicator from this platform only.
 * The relationship is revoked; the connector removes the indicator and reports removed,
 * otherwise the deployment manager flags it expired after the grace period.
 */
export const removeIndicatorDeployment = async (context: AuthContext, user: AuthUser, id: string) => {
  const relation = await loadDeployedOnById(context, user, id);
  // Same pair lock as a retry and the connector reports: a concurrent retry never undoes the withdrawal.
  const lock = await lockResources([pairLockKey(relation.fromId, relation.toId)]);
  try {
    const current = await loadDeployedOnById(context, user, id);
    if (current.revoked === true) {
      return current;
    }
    const { element } = await patchAttribute(context, user, current.internal_id, RELATION_DEPLOYED_ON, { revoked: true });
    await setRemovalRequestedAt(context, current, new Date());
    return await notifyRelationEdit(user, element);
  } finally {
    await lock.unlock();
  }
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

// Page size of the scan counting the live deployments of expired or revoked indicators.
const EXPIRED_SCAN_PAGE_SIZE = 5000;

const expiredDeployedIndicatorGroups = (now: string) => [filterGroup([
  { key: ['revoked'], values: [true] },
  { key: ['valid_until'], values: [now], operator: 'lt' },
], [], 'or')];

/**
 * Live deployments of one security platform matching the filters whose indicator is revoked or past its valid_until:
 * still on the platform during the removal grace period, before the manager flags them expired. Only indicators the
 * reader can access are counted. The scan pages over the smaller side, one page in memory at a time: the expired
 * indicators with a deployment on the platform, or the live deployments of the platform (one per indicator).
 */
const countLiveDeploymentsOfExpiredIndicators = async (
  context: AuthContext,
  user: AuthUser,
  platformId: string,
  deploymentFilters: FilterContent[],
  liveDeployments: number,
  now: string,
) => {
  if (liveDeployments === 0) return 0;
  const pageArgs = (after?: string) => ({ first: EXPIRED_SCAN_PAGE_SIZE, after, orderBy: 'internal_id', orderMode: 'asc', baseData: true, noFiltersChecking: true });
  const nextCursor = (pageInfo: { hasNextPage?: boolean; endCursor?: unknown }) => {
    return pageInfo.hasNextPage && pageInfo.endCursor ? String(pageInfo.endCursor) : undefined;
  };
  const expiredPage = (after?: string) => pageRegardingEntitiesConnection<BasicStoreEntityIndicator>(
    context,
    user,
    platformId,
    RELATION_DEPLOYED_ON,
    ENTITY_TYPE_INDICATOR,
    true,
    { ...pageArgs(after), filters: filterGroup([], expiredDeployedIndicatorGroups(now)) } as never,
  );
  let total = 0;
  let page = await expiredPage();
  if ((page.pageInfo.globalCount ?? 0) <= liveDeployments) {
    for (;;) {
      const ids = page.edges.map((edge) => edge.node.internal_id);
      if (ids.length > 0) total += await countDeployments(context, user, [...deploymentFilters, { key: ['fromId'], values: ids }]);
      const after = nextCursor(page.pageInfo);
      if (!after) return total;
      page = await expiredPage(after);
    }
  }
  let after: string | undefined;
  do {
    const livePage = await pageRelationsConnection<BasicStoreRelationDeployedOn>(context, user, RELATION_DEPLOYED_ON, {
      ...pageArgs(after),
      filters: filterGroup(deploymentFilters),
    } as never);
    const ids = [...new Set(livePage.edges.map((edge) => edge.node.fromId))];
    if (ids.length > 0) total += await countIndicators(context, user, [{ key: ['internal_id'], values: ids }], expiredDeployedIndicatorGroups(now));
    after = nextCursor(livePage.pageInfo);
  } while (after);
  return total;
};

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
  // Disseminated means reported by a connector (see isReportedDeployment)
  const reportedFilter: FilterContent = { key: ['last_sync_at'], values: [], operator: 'not_nil' as never };
  let funnel;
  if (args.platformId) {
    // Expired still deployed: flagged expired (removal never confirmed), or still live while the indicator is revoked or past valid_until.
    const [disseminated, deployed, validated, hit, flaggedExpired] = await Promise.all([
      countDeployments(context, user, [...baseDeploymentFilters, reportedFilter]),
      countDeployments(context, user, [...baseDeploymentFilters, liveFilter]),
      countDeployments(context, user, [...baseDeploymentFilters, provenFilter]),
      countDeployments(context, user, [...baseDeploymentFilters, { key: ['hit_count'], values: [0], operator: 'gt' }]),
      countDeployments(context, user, [...baseDeploymentFilters, { key: ['deployment_status'], values: [DEPLOYMENT_STATUS_EXPIRED] }]),
    ]);
    const liveOfExpired = await countLiveDeploymentsOfExpiredIndicators(context, user, args.platformId, [...baseDeploymentFilters, liveFilter], deployed, now);
    funnel = { created: disseminated, disseminated, deployed, validated, hit, expired_still_deployed: flaggedExpired + liveOfExpired };
  } else {
    const createdDates = dateRangeFilters('created_at', args.startDate, args.endDate);
    const isDeployed: FilterContent = { key: [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT], values: [0], operator: 'gt' };
    // Disseminated: a stream connector recorded the indicator on a platform, whatever the outcome.
    const isDisseminated: FilterContent = { key: [INDICATOR_DEPLOYMENTS_COUNT], values: [0], operator: 'gt' };
    // Expired still deployed: expired or revoked but still live, or flagged expired (removal never confirmed).
    const expiredStillDeployedGroup = filterGroup([
      { key: [INDICATOR_DEPLOYMENT_EXPIRED_COUNT], values: [0], operator: 'gt' },
    ], [filterGroup([isDeployed], [filterGroup([
      { key: ['revoked'], values: [true] },
      { key: ['valid_until'], values: [now], operator: 'lt' },
    ], [], 'or')])], 'or');
    const [created, disseminated, deployed, validated, hit, expired] = await Promise.all([
      countIndicators(context, user, createdDates),
      countIndicators(context, user, [...createdDates, isDisseminated]),
      countIndicators(context, user, [...createdDates, isDeployed]),
      countIndicators(context, user, [...createdDates, { key: [INDICATOR_VALIDATED_PLATFORMS_COUNT], values: [0], operator: 'gt' }]),
      countIndicators(context, user, [...createdDates, { key: [INDICATOR_HIT_PLATFORMS_COUNT], values: [0], operator: 'gt' }]),
      countIndicators(context, user, createdDates, [expiredStillDeployedGroup]),
    ]);
    funnel = { created, disseminated, deployed, validated, hit, expired_still_deployed: expired };
  }
  const aggregate = async (field: string) => {
    const buckets = await elAggregationCount(context, user, READ_RELATIONSHIPS_INDICES, {
      types: [RELATION_DEPLOYED_ON],
      field,
      normalizeLabel: false,
      filters: filterGroup([...baseDeploymentFilters, reportedFilter]),
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
const EXPIRY_SCAN_CURSOR_STATE = 'indicator_deployment_expiry_scan';

type RemovalTracked = { revoked?: boolean | null; removal_requested_at?: unknown };
type RemovalSource = { valid_until?: unknown; revoked?: boolean | null };

/** Whether the removal of a deployment is requested: withdrawn from its security platform, or its indicator revoked. */
export const isRemovalRequested = (deployment: RemovalTracked, indicator?: RemovalSource | null) => {
  return deployment.revoked === true || indicator?.revoked === true;
};

/**
 * Whether the connector had the grace period to confirm the removal of a live deployment. The period starts at the end
 * of validity of the indicator, or when the removal was requested (removal_requested_at): later edits of the indicator
 * or of the deployment move neither.
 */
export const isRemovalOverdue = (deployment: RemovalTracked, indicator: RemovalSource | null | undefined, threshold: string) => {
  const before = (value: unknown) => !!value && new Date(value as string).getTime() < new Date(threshold).getTime();
  return before(indicator?.valid_until) || (isRemovalRequested(deployment, indicator) && before(deployment.removal_requested_at));
};

// A deployment withdrawn before the revocation of its indicator keeps the start of its own grace period.
const RECORD_REVOCATION_SCRIPT = 'if (ctx._source.revoked != true || ctx._source.removal_requested_at == null) {'
  + ' ctx._source.removal_requested_at = params.at; } else { ctx.op = \'noop\'; }';

/**
 * Starts the removal grace period of the live deployments of revoked indicators at the time of each revocation event,
 * so a replayed event writes the same value.
 */
export const recordIndicatorRevocations = async (context: AuthContext, revocations: Map<string, string>) => {
  if (revocations.size === 0) {
    return 0;
  }
  const deployments = await fullRelationsList<BasicStoreRelationDeployedOn & { _index: string }>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    fromId: [...revocations.keys()],
    filters: { mode: 'and' as never, filters: [{ key: ['deployment_status'], values: LIVE_DEPLOYMENT_STATUSES }], filterGroups: [] },
    noFiltersChecking: true,
  } as never);
  await BluePromise.map(deployments, async (deployment) => {
    const script = { source: RECORD_REVOCATION_SCRIPT, lang: 'painless', params: { at: revocations.get(deployment.fromId) } };
    await elUpdate(context, deployment._index, deployment.internal_id, { script });
  }, { concurrency: BATCH_CONCURRENCY });
  return deployments.length;
};

/**
 * Under the pair and indicator locks, records the start of the removal grace period of a live deployment whose removal
 * is requested without one (withdrawal or revocation by a regular edit or an import, event missed while the manager was
 * stopped), or clears it once the removal is no longer requested (indicator reinstated).
 */
const syncRemovalRequest = async (context: AuthContext, relation: BasicStoreRelationDeployedOn) => {
  const lock = await lockResources([pairLockKey(relation.fromId, relation.toId), relation.fromId]);
  try {
    const current = await findDeployedOn(context, SYSTEM_USER, relation.fromId, relation.toId);
    if (!current || !LIVE_DEPLOYMENT_STATUSES.includes(current.deployment_status)) {
      return;
    }
    const indicator = await storeLoadById<BasicStoreEntityIndicator>(context, SYSTEM_USER, relation.fromId, ENTITY_TYPE_INDICATOR);
    const requested = isRemovalRequested(current, indicator);
    if (requested !== isNotEmptyField(current.removal_requested_at)) {
      await setRemovalRequestedAt(context, current, requested ? new Date() : null);
    }
  } finally {
    await lock.unlock();
  }
};

/**
 * Indicators that expired or were revoked are removed by the connectors through the stream events they already consume
 * (revocation update, or delete event on filtered streams), and so are deployments withdrawn by an analyst (revoked relationship).
 * Live deployments without removal confirmation after the grace period are flagged expired:
 * a regular update, so history, stream and triggers ("expired but still deployed") see it.
 */
export const flagExpiredDeployments = async (context: AuthContext, user: AuthUser, gracePeriodMs: number, batchSize: number) => {
  const threshold = new Date(Date.now() - gracePeriodMs).toISOString();
  const liveFilter = { key: ['deployment_status'], values: LIVE_DEPLOYMENT_STATUSES };
  // The live deployments themselves are scanned, one resumable page per run: the counters stored on the indicators
  // leave out the deployments some readers cannot see, so they cannot select the candidates.
  const after = (await redisGetManagerEventState(EXPIRY_SCAN_CURSOR_STATE)) || undefined;
  const livePage = await pageRelationsConnection<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    first: batchSize,
    after,
    orderBy: 'internal_id',
    orderMode: 'asc',
    filters: { mode: 'and' as never, filters: [liveFilter], filterGroups: [] },
    noFiltersChecking: true,
  } as never);
  const scanDone = !livePage.pageInfo.hasNextPage || !livePage.pageInfo.endCursor;
  await redisSetManagerEventState(EXPIRY_SCAN_CURSOR_STATE, scanDone ? '' : String(livePage.pageInfo.endCursor));
  const liveDeployments = livePage.edges.map((edge) => edge.node);
  const sourceIds = [...new Set(liveDeployments.map((deployment) => deployment.fromId))];
  const sources = sourceIds.length === 0 ? [] : await storeLoadByIds<BasicStoreEntityIndicator>(context, SYSTEM_USER, sourceIds, ENTITY_TYPE_INDICATOR);
  const indicators = new Map(sources.filter((indicator) => indicator).map((indicator) => [indicator.internal_id, indicator]));
  // A removal request recorded now starts its grace period now: it is never flagged in this run
  const unsynced = liveDeployments.filter((deployment) => {
    return isRemovalRequested(deployment, indicators.get(deployment.fromId)) !== isNotEmptyField(deployment.removal_requested_at);
  });
  await BluePromise.map(unsynced, async (relation) => {
    try {
      await syncRemovalRequest(context, relation);
    } catch (error) {
      logApp.warn('[DISSEMINATION] Cannot record the removal request of a deployment, left to a later scan', { cause: error, id: relation.internal_id });
    }
  }, { concurrency: BATCH_CONCURRENCY });
  const overdueOnPage = liveDeployments.filter((deployment) => isRemovalOverdue(deployment, indicators.get(deployment.fromId), threshold));
  const withdrawn = await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    filters: {
      mode: 'and' as never,
      filters: [liveFilter, { key: ['revoked'], values: [true] }, { key: ['removal_requested_at'], values: [threshold], operator: 'lt' as never }],
      filterGroups: [],
    },
    noFiltersChecking: true,
    maxSize: batchSize,
  } as never);
  const toFlag = new Map<string, BasicStoreRelationDeployedOn>();
  [...overdueOnPage, ...withdrawn].forEach((relation) => toFlag.set(relation.internal_id, relation));
  let flagged = 0;
  let failed = 0;
  await BluePromise.map([...toFlag.values()], async (relation) => {
    try {
      // A report can land between the scan and this write: recheck under the pair lock of the report path.
      // A relation changed since the scan is left to the next run, which sees its new state. The indicator is
      // locked too (its edits lock it) and read again: one renewed since the scan keeps its deployments live.
      const lock = await lockResources([pairLockKey(relation.fromId, relation.toId), relation.fromId]);
      try {
        const current = await findDeployedOn(context, SYSTEM_USER, relation.fromId, relation.toId);
        const unchanged = current && String(current.updated_at) === String(relation.updated_at);
        const indicator = await storeLoadById<BasicStoreEntityIndicator>(context, SYSTEM_USER, relation.fromId, ENTITY_TYPE_INDICATOR);
        const eligible = !!current && isRemovalOverdue(current, indicator, threshold);
        if (current && unchanged && eligible && LIVE_DEPLOYMENT_STATUSES.includes(current.deployment_status)) {
          const { element } = await patchAttribute(context, user, current.internal_id, RELATION_DEPLOYED_ON, { deployment_status: DEPLOYMENT_STATUS_EXPIRED });
          await notifyRelationEdit(user, element);
          flagged += 1;
        }
      } finally {
        await lock.unlock();
      }
    } catch (error) {
      // Still live, so a later scan flags it
      failed += 1;
      logApp.warn('[DISSEMINATION] Cannot flag deployment as expired, left to a later scan', { cause: error, id: relation.internal_id });
    }
  }, { concurrency: BATCH_CONCURRENCY });
  if (flagged > 0) {
    await refreshIndicatorDeploymentCounters(context, [...toFlag.values()].map((r) => r.fromId));
    logApp.info('[DISSEMINATION] Deployments flagged as expired', { flagged });
  }
  if (failed > 0) {
    logApp.warn('[DISSEMINATION] Deployments left to a later expiry scan', { errors_count: failed, total_count: toFlag.size });
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
export const COUNTER_FIELDS = [
  INDICATOR_DEPLOYMENTS_COUNT,
  INDICATOR_DEPLOYMENT_PLATFORMS_COUNT,
  INDICATOR_DEPLOYMENT_FAILED_COUNT,
  INDICATOR_DEPLOYMENT_EXPIRED_COUNT,
  INDICATOR_VALIDATED_PLATFORMS_COUNT,
  INDICATOR_HIT_PLATFORMS_COUNT,
];

/**
 * Indicators created before dissemination assurance (or before a counter was added) lack counters
 * (new ones get 0 by default value). They are backfilled in bounded batches by the deployment manager
 * instead of a blocking startup migration. A missing counter says nothing about the deployments: an older
 * indicator can get a deployed-on relationship (bundle import, manager stopped) before its first backfill.
 * Each batch is therefore checked against its relationships: indicators without any get 0 in one bulk
 * update, the others are recomputed from their relationships.
 * Idempotent: only documents missing a counter are touched, a counter already set is never overwritten,
 * no stream event, no history.
 */
export const backfillIndicatorDeploymentCounters = async (context: AuthContext, batchSize: number) => {
  const missing = await fullEntitiesList<BasicStoreEntityIndicator>(context, SYSTEM_USER, [ENTITY_TYPE_INDICATOR], {
    filters: {
      mode: 'or' as never,
      filters: COUNTER_FIELDS.map((field) => ({ key: [field], values: [], operator: 'nil' as never })),
      filterGroups: [],
    },
    noFiltersChecking: true,
    baseData: true,
    maxSize: batchSize,
  } as never);
  if (missing.length === 0) {
    return 0;
  }
  const missingIds = missing.map((indicator) => indicator.internal_id);
  const relations = await fullRelationsList<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, { fromId: missingIds });
  const deployedIds = new Set(relations.map((relation) => relation.fromId));
  const withoutDeployment = missingIds.filter((id) => !deployedIds.has(id));
  let initialized = 0;
  if (withoutDeployment.length > 0) {
    const result = await elRawUpdateByQuery({
      index: READ_INDEX_STIX_DOMAIN_OBJECTS,
      refresh: true,
      conflicts: 'proceed',
      body: {
        script: { source: COUNTERS_BACKFILL_SOURCE, lang: 'painless', params: { fields: COUNTER_FIELDS } },
        query: {
          bool: {
            must: [
              { term: { 'entity_type.keyword': { value: ENTITY_TYPE_INDICATOR } } },
              { terms: { 'internal_id.keyword': withoutDeployment } },
            ],
          },
        },
      },
    }) as { updated?: number };
    initialized = result?.updated ?? 0;
  }
  const recomputed = await refreshIndicatorDeploymentCounters(context, [...deployedIds]);
  return initialized + recomputed;
};

const RECONCILIATION_CURSOR_STATE = 'indicator_deployment_counters_reconciliation';

/**
 * Rolling reconciliation of the counters of every indicator with a positive counter, one page per call.
 * Deleting a Security Platform (or trashing, merging, restoring it) cascades to its deployed-on relationships
 * without any relationship event, so the counters of the indicators cannot be refreshed from the stream.
 * The cursor is kept in Redis; the scan restarts from the beginning once the end is reached.
 * @returns the number of indicators checked and whether the scan reached the end.
 */
const reconcileCountersPage = async (context: AuthContext, batchSize: number, after: string | undefined) => {
  const page = await pageEntitiesConnection<BasicStoreEntityIndicator>(context, SYSTEM_USER, [ENTITY_TYPE_INDICATOR], {
    first: batchSize,
    after,
    orderBy: 'internal_id',
    orderMode: 'asc',
    filters: {
      mode: 'or' as never,
      filters: COUNTER_FIELDS.map((field) => ({ key: [field], values: [0], operator: 'gt' as never })),
      filterGroups: [],
    },
    noFiltersChecking: true,
  } as never);
  const ids = page.edges.map((edge) => edge.node.internal_id);
  const updated = await refreshIndicatorDeploymentCounters(context, ids);
  const done = !page.pageInfo.hasNextPage || !page.pageInfo.endCursor;
  return { checked: ids.length, updated, done, endCursor: done ? undefined : String(page.pageInfo.endCursor) };
};

export const reconcileIndicatorDeploymentCounters = async (context: AuthContext, batchSize: number) => {
  const after = (await redisGetManagerEventState(RECONCILIATION_CURSOR_STATE)) || undefined;
  const { checked, updated, done, endCursor } = await reconcileCountersPage(context, batchSize, after);
  await redisSetManagerEventState(RECONCILIATION_CURSOR_STATE, endCursor ?? '');
  return { checked, updated, done };
};

const DEPLOYED_RECONCILIATION_CURSOR_STATE = 'indicator_deployment_deployed_reconciliation';

/**
 * Rolling reconciliation driven by the deployed-on relationships, one page per call: the counters of an
 * indicator can be at their default 0 while deployments exist (relationships written while the manager was
 * stopped or before its first start, outside the stream it resumes), and the scan above never selects an
 * indicator without a positive counter. Only mismatching counters are written.
 * @returns the number of relationships checked, the counters updated and whether the scan reached the end.
 */
export const reconcileDeployedIndicatorCounters = async (context: AuthContext, batchSize: number) => {
  const after = (await redisGetManagerEventState(DEPLOYED_RECONCILIATION_CURSOR_STATE)) || undefined;
  const page = await pageRelationsConnection<BasicStoreRelationDeployedOn>(context, SYSTEM_USER, RELATION_DEPLOYED_ON, {
    first: batchSize,
    after,
    orderBy: 'internal_id',
    orderMode: 'asc',
  } as never);
  const updated = await refreshIndicatorDeploymentCounters(context, page.edges.map((edge) => edge.node.fromId));
  const done = !page.pageInfo.hasNextPage || !page.pageInfo.endCursor;
  await redisSetManagerEventState(DEPLOYED_RECONCILIATION_CURSOR_STATE, done ? '' : String(page.pageInfo.endCursor));
  return { checked: page.edges.length, updated, done };
};

/**
 * Full reconciliation pass, from the beginning, bounded by maxPages (after a Security Platform deletion). It keeps its
 * own cursor: the periodic pass, run under another lock, never moves it past pages it has not checked, nor the reverse.
 */
export const reconcileAllIndicatorDeploymentCounters = async (context: AuthContext, batchSize: number, maxPages: number) => {
  let updated = 0;
  let after: string | undefined;
  for (let pageIndex = 0; pageIndex < maxPages; pageIndex += 1) {
    const result = await reconcileCountersPage(context, batchSize, after);
    updated += result.updated;
    if (result.done) {
      break;
    }
    after = result.endCursor;
  }
  return updated;
};

/**
 * Streams an indicator update when a revoked indicator is live on a platform while the stream last showed it live
 * nowhere: its revocation was streamed before the counters caught up with its first deployment, or a deployment was
 * reported after the revocation. Counters are written without stream event, so a trigger on revoked indicators still
 * deployed only sees them through such an event; stream consumers see the revoked indicator again, as on revocation.
 */
const streamRevokedIndicatorStillDeployed = async (context: AuthContext, indicatorId: string, counters: IndicatorDeploymentCounters) => {
  const instance = await storeLoadByIdWithRefs(context, SYSTEM_USER, indicatorId, { type: ENTITY_TYPE_INDICATOR });
  if (!instance) {
    return;
  }
  const previous = { ...instance, [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT]: 0 };
  const current = { ...instance, ...counters };
  const changes = [{ field: 'Deployment platforms count', previous: ['0'], new: [String(counters[INDICATOR_DEPLOYMENT_PLATFORMS_COUNT])] }];
  await storeUpdateEvent(context, SYSTEM_USER, previous, current, changes, { noHistory: true });
};

/**
 * Recompute the derived deployment counters of the given indicators from their deployed-on relationships.
 * Runs as system user: only numbers are stored on the indicator, and only the deployments every reader of the indicator
 * can read are counted, so a deployment on a more restricted security platform is never revealed by a counter.
 * Side-channel update: no stream event, no history, updated_at kept, except for a revoked indicator found live while
 * the stream showed it live nowhere (see streamRevokedIndicatorStillDeployed). What the stream last showed is the
 * stored counter, or, for the stream handler, what the last indicator event it read showed (streamedLive).
 */
export const refreshIndicatorDeploymentCounters = async (context: AuthContext, indicatorIds: string[], streamedLive: Map<string, boolean> = new Map()) => {
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
  const platformIds = [...new Set(relations.map((relation) => relation.toId))];
  const platforms = platformIds.length === 0
    ? []
    : await storeLoadByIds<BasicStoreEntitySecurityPlatform>(context, SYSTEM_USER, platformIds, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  const platformsById = new Map(platforms.filter((platform) => platform).map((platform) => [platform.internal_id, platform]));
  // Organization sharing only restricts reads when a platform organization is set
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const enforced = !!settings?.platform_organization;
  const creatorIds = enforced ? [...new Set(indicators.map((indicator) => indicator[RELATION_CREATED_BY]).filter((id): id is string => !!id))] : [];
  const individuals = creatorIds.length === 0 ? [] : await storeLoadByIds<BasicStoreEntity>(context, SYSTEM_USER, creatorIds, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
  const organizationSharing = { enforced, individualIds: new Set(individuals.filter((individual) => individual).map((individual) => individual.internal_id)) };
  const markingDefinitions = await getEntitiesMapFromCache<BasicStoreEntity & { definition_type: string; x_opencti_order: number }>(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_MARKING_DEFINITION,
  );
  const markingRanks = new Map<string, { type: string; order: number }>();
  markingDefinitions.forEach((marking) => markingRanks.set(marking.internal_id, { type: marking.definition_type, order: marking.x_opencti_order }));
  let updated = 0;
  await BluePromise.map(indicators, async (indicator) => {
    const readable = (relationsByIndicator.get(indicator.internal_id) ?? [])
      .filter((relation) => platformsById.has(relation.toId)
        && isReadableWithIndicator(relation, indicator, platformsById.get(relation.toId), organizationSharing, markingRanks));
    const counters = computeIndicatorDeploymentCounters(readable);
    const unchanged = (Object.keys(counters) as Array<keyof IndicatorDeploymentCounters>)
      .every((key) => (indicator[key] ?? 0) === counters[key] && indicator[key] !== undefined);
    if (!unchanged) {
      const params = buildReplaceScriptParams(counters);
      await elUpdate(context, indicator._index, indicator.internal_id, { script: { source: EL_REPLACE_SCRIPT_SOURCE, lang: 'painless', params } });
      // Live update of the open indicator screens only: still no stream event
      await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, { ...indicator, ...counters }, SYSTEM_USER);
      updated += 1;
    }
    const shownLive = streamedLive.get(indicator.internal_id) ?? (indicator[INDICATOR_DEPLOYMENT_PLATFORMS_COUNT] ?? 0) > 0;
    if (indicator.revoked && counters[INDICATOR_DEPLOYMENT_PLATFORMS_COUNT] > 0 && !shownLive) {
      await streamRevokedIndicatorStillDeployed(context, indicator.internal_id, counters);
    }
  }, { concurrency: BATCH_CONCURRENCY });
  return updated;
};
// endregion
