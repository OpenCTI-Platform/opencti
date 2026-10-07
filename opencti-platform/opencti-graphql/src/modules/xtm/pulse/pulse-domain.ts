import { createHash } from 'node:crypto';
import DataLoader from 'dataloader';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import type { BasicStoreEntity, StoreMarkingDefinition } from '../../../types/store';
import conf, { BUS_TOPICS, logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../database/cache';
import { elCount } from '../../../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../database/utils';
import { updateAttribute } from '../../../database/middleware';
import { fullEntitiesList, internalLoadById, storeLoadById } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import { executionContext, PULSE_MANAGER_USER, SYSTEM_USER } from '../../../utils/access';
import { publishUserAction } from '../../../listener/UserActionListener';
import { isEnterpriseEdition } from '../../../enterprise-edition/ee';
import { getSettings, getSettingsFromDatabase } from '../../../domain/settings';
import { addThreatPulseLookupsCount, addThreatPulseModeChangeCount, addThreatPulsePreviewEventCount, addThreatPulseRecordsCount } from '../../../manager/telemetryManager';
import { lockResources } from '../../../lock/master-lock';
import {
  FilterMode,
  FilterOperator,
  type FilterGroup,
  PulseAccess,
  type PulseConfigurationInput,
  PulseContributionStatus,
  PulseMode,
  PulsePeriod,
  PulseRegionBucket,
  PulseSectorBucket,
  type PulseSurface,
  type PulseTelemetryEvent,
  PulseUnavailableReason,
} from '../../../generated/graphql';
import { PulseHubError, type PulseHubPlatform, xtmHubPulseClient } from '../hub/xtm-hub-pulse-client';
import {
  aggregatePulseActivity,
  boundPulseWindow,
  buildPulseOutboxItems,
  collectPulseActivity,
  countPulseActivity,
  loadPulseEntities,
  mergePulseActivity,
  type PulseActivity,
  type PulseCollectBudget,
} from './pulse-collector';
import { computeStableKeys, computeTransportHash, decodeTransportHash, isValidPulseHash } from './pulse-hashing';
import {
  buildPulseDocument,
  buildPulsePreviewDocument,
  clearPulseNetworkInformation,
  combinePulseLookups,
  combinePulsePreviewSignals,
  isPulsePreviewDocument,
  PULSE_PREVIEW_CLEARED_DOCUMENT,
  toDayDate,
  type PulseClearScope,
  type PulseDocumentUpdate,
  type PulseFieldPolicy,
  type PulsePreviewSignal,
  toPulseInformationOutput,
  visiblePulseInformation,
  writePulseDocuments,
  PULSE_QUERYABLE_ATTRIBUTES,
  PULSE_SORTABLE_ATTRIBUTES,
  pulseQueryClause,
  pulseVisibleSort,
} from './pulse-information';
import { registerAttributeQueryGate } from '../../../database/engine-attribute-gates';
import { registerSortingOverride } from '../../../utils/sorting';
import {
  buildPulseMarkingPolicy,
  getForcedExcludedMarkings,
  getPulseAccess,
  hasPulseReadAccess,
  getPulseBuckets,
  getPulseHubPlatform,
  isPulseContributable,
  isPulseResolvedContributable,
  isPulseContributing,
  readPulseSettings,
  suggestPulseBuckets,
} from './pulse-settings';
import {
  redisDeletePulseResponse,
  redisClaimPulseOutbox,
  redisBumpPulseConfigGeneration,
  redisBumpPulsePolicyGeneration,
  redisCommitPulseWindow,
  redisDiscardPulseActivity,
  redisDiscardPulseAdmission,
  redisDiscardPulseOutbox,
  redisClearPulseContributionState,
  redisGetPulseAdmission,
  redisGetPulseContributionStats,
  redisGetPulseConfigGeneration,
  redisGetPulsePolicyGeneration,
  redisGetPulseCursor,
  redisGetPulseEntityLookup,
  redisGetPulseResponse,
  redisGetPulseSalt,
  redisGetPulseState,
  redisSettlePulseOutboxEntry,
  redisSetPulseAdmission,
  redisSetPulseCursor,
  redisSetPulseEntityLookup,
  redisSetPulseResponse,
  redisSetPulseSalt,
  redisSetPulseState,
  redisTakePulseActivity,
  type PulseExternalActivity,
  type PulseOperationalState,
  type PulseWindowSighting,
} from './pulse-cache';
import { refreshPulseStixPolicy, registerPulseStixPolicyRefresher, setPulseStixPolicy } from './pulse-stix-policy';
import {
  type BasicStorePulseEntity,
  PULSE_CONSENT_VERSION,
  PULSE_ENTITY_TYPE_BY_OBJECT_TYPE,
  PULSE_MAX_LOOKUP_HASHES,
  PULSE_MODE_VALUES,
  PULSE_OBJECT_TYPE_BY_ENTITY_TYPE,
  PULSE_SCOPE_ENTITY_TYPES,
  PULSE_SETTINGS_CONSENT_DATE,
  PULSE_SETTINGS_CONSENT_USER,
  PULSE_SETTINGS_CONSENT_VERSION,
  PULSE_SETTINGS_EXCLUDED_MARKINGS,
  PULSE_SETTINGS_ID,
  PULSE_SETTINGS_MODE,
  PULSE_SETTINGS_REGION,
  PULSE_SETTINGS_SCOPES,
  PULSE_SETTINGS_SECTOR,
  PULSE_STATUS_ID,
  type PulseHubDigest,
  type PulseHubLookupResult,
  type PulseHubStatus,
  type PulseHubTrendingItem,
  type PulseHubTrendingResult,
  type PulseObjectType,
  type PulseOutboxItem,
  type PulsePeriodValue,
  type PulseRegionBucketValue,
  type PulseSectorBucketValue,
  type PulseSettingsOutput,
  type PulseSettingsValues,
} from './pulse-types';

const ONE_DAY_MS = 24 * 3600 * 1000;
const PULSE_PUSH_LOCK_KEY = conf.get('pulse_manager:push_lock_key') || 'pulse_push_lock';

// One lock for what reaches XTM Hub or writes community data (a push, a page of the nightly refresh or of the preview)
// and for what changes the policy (a narrowing configuration, a purge): neither runs halfway through the other.
const withPulsePushLock = async <T>(run: () => Promise<T>): Promise<T> => {
  const lock = await lockResources([PULSE_PUSH_LOCK_KEY]);
  try {
    return await run();
  } finally {
    await lock.unlock();
  }
};
const LOOKUP_CACHE_TTL_SECONDS = conf.get('pulse_manager:lookup_cache_ttl_seconds') ?? 6 * 3600;
const RESPONSE_CACHE_TTL_SECONDS = conf.get('pulse_manager:response_cache_ttl_seconds') ?? 900;
const STATUS_CACHE_TTL_SECONDS = 300;
const MAX_WINDOW_HOURS = conf.get('pulse_manager:max_window_hours') ?? 24;
const MAX_EVENTS_PER_RUN = conf.get('pulse_manager:max_events_per_run') ?? 100000;
const REFRESH_INTERVAL_MS = conf.get('pulse_manager:refresh_interval') ?? ONE_DAY_MS;
const REFRESH_MAX_ENTITIES = conf.get('pulse_manager:refresh_max_entities') ?? 200000;
const PREVIEW_MAX_ENTITIES = conf.get('pulse_manager:preview_max_entities') ?? 1000000;
const STATS_DAYS = 30;
// Days of external activity kept in Redis (the salt days XTM Hub keeps).
const ACTIVITY_DAYS = 3;
const DEFAULT_TRENDING_SIZE = 50;
const MAX_TRENDING_SIZE = 200;

// region time helpers
export const utcDay = (date = new Date()) => date.toISOString().slice(0, 10);

export const previousUtcDay = (day: string) => utcDay(new Date(Date.parse(`${day}T00:00:00.000Z`) - ONE_DAY_MS));

export const lastUtcDays = (count: number, from = new Date()) => {
  return Array.from({ length: count }, (_, index) => utcDay(new Date(from.getTime() - (count - 1 - index) * ONE_DAY_MS)));
};

// [since, until) cut at every UTC midnight, each part with its day.
export const utcDaySegments = (since: Date, until: Date) => {
  const segments: Array<{ day: string; since: Date; until: Date }> = [];
  let start = since;
  while (start.getTime() < until.getTime()) {
    const day = utcDay(start);
    const end = new Date(Math.min(until.getTime(), Date.parse(`${day}T00:00:00.000Z`) + ONE_DAY_MS));
    segments.push({ day, since: start, until: end });
    start = end;
  }
  return segments;
};
// endregion

// `fresh` reads the settings from the database rather than the cache another node may not have refreshed yet.
const loadPulseContext = async (context: AuthContext, { fresh = false } = {}) => {
  const settings = fresh
    ? await getSettingsFromDatabase(context) as BasicStoreSettings
    : await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const values = readPulseSettings(settings);
  const platform = getPulseHubPlatform(settings);
  const state = await redisGetPulseState();
  const access = getPulseAccess(values, platform !== null, hasPulseReadAccess(state));
  return { settings, values, platform, state, access };
};

registerPulseStixPolicyRefresher(async () => {
  const context = executionContext('pulse_stix_policy');
  const { values, state, access } = await loadPulseContext(context);
  const markingPolicy = access === PulseAccess.Full ? await buildPulseMarkingPolicy(context, values) : null;
  return {
    access,
    scopes: values.scopes,
    cleanupPending: state.cleanup_pending !== undefined,
    isContributable: markingPolicy ? (instance) => isPulseResolvedContributable(instance, markingPolicy, values.scopes) : null,
  };
});

// The node that changes the configuration or cleans the data carries the new state in STIX at once; the other nodes
// within the refresh interval of the snapshot.
const refreshPulseStixPolicyNow = () => refreshPulseStixPolicy().catch(() => setPulseStixPolicy(null));

// Read before the API and the managers start: the first conversion of a node carries what the policy allows instead of
// nothing. A failed read keeps the data hidden until a background refresh succeeds.
export const initializePulseStixPolicy = () => refreshPulseStixPolicyNow();

// region cleanup
// The community data of the platform goes whenever it stops being current: unregistration, purge, lapse, the opening
// of the full experience, a configuration that changes the mode or takes objects out. The cleanup can fail
// (Elasticsearch, Redis): the pending marker - with the scope of a partial cleanup - is written before it and removed
// once it succeeded, and every manager cycle replays a pending cleanup, registered on XTM Hub or not. A cleanup that
// completes a state transition (opening) completes it when replayed.
const PULSE_CLEANUPS = ['registration', 'opening', 'network', 'scope'] as const;
type PulseCleanup = typeof PULSE_CLEANUPS[number];

const readPendingScope = (state: PulseOperationalState): PulseClearScope => {
  try {
    const scope = JSON.parse(state.cleanup_scope ?? '{}');
    return { entityTypes: scope.entityTypes ?? [], markingIds: scope.markingIds ?? [] };
  } catch {
    return { entityTypes: [], markingIds: [] };
  }
};

const runPulseCleanup = async (cleanup: PulseCleanup, scope: PulseClearScope) => {
  if (cleanup === 'registration') {
    // The registration is gone: what was collected for it goes with its contribution state.
    await redisDiscardPulseOutbox();
    await redisDiscardPulseActivity(lastUtcDays(ACTIVITY_DAYS));
    await redisSetPulseState({
      contribution_accepted: undefined,
      contribution_lapsed: undefined,
      last_refresh_at: undefined,
      refresh_offset: undefined,
      preview_refresh_at: undefined,
      preview_offset: undefined,
      preview_scan_start: undefined,
      preview_matched: undefined,
      preview_since: undefined,
    });
  }
  await clearPulseNetworkInformation(cleanup === 'scope' ? scope : undefined);
  // XTM Hub accepted a contribution: once the preview signal is gone, the full experience opens.
  const opened = cleanup === 'opening' ? { contribution_accepted: 'true', contribution_lapsed: undefined, last_refresh_at: undefined, preview_matched: undefined } : {};
  await redisSetPulseState({ ...opened, cleanup_pending: undefined, cleanup_scope: undefined });
};

// Whether the cleanup succeeded: a failure is logged and left to the next manager cycle. A pending cleanup of the
// registration covers any other; otherwise the latest one decides the state to reach, and a partial cleanup joins a
// pending partial one or is covered by a pending full one. Runs under the push lock, like every cleanup.
const cleanupPulseData = async (cleanup: PulseCleanup, scope: PulseClearScope = { entityTypes: [], markingIds: [] }) => {
  let pending: PulseCleanup = cleanup;
  try {
    const state = await redisGetPulseState();
    const current = PULSE_CLEANUPS.find((value) => value === state.cleanup_pending);
    let pendingScope = scope;
    if (current === 'registration' || (cleanup === 'scope' && current && current !== 'scope')) {
      pending = current;
    } else if (cleanup === 'scope' && current === 'scope') {
      const previous = readPendingScope(state);
      pendingScope = {
        entityTypes: Array.from(new Set([...previous.entityTypes, ...scope.entityTypes])),
        markingIds: Array.from(new Set([...previous.markingIds, ...scope.markingIds])),
      };
    }
    await redisSetPulseState({ cleanup_pending: pending, cleanup_scope: pending === 'scope' ? JSON.stringify(pendingScope) : undefined });
    await runPulseCleanup(pending, pendingScope);
    return true;
  } catch (error) {
    logApp.error('[THREAT PULSE] Community data not cleaned, the next manager cycle retries', { cause: error, cleanup: pending });
    return false;
  } finally {
    await refreshPulseStixPolicyNow();
  }
};

const findPendingCleanup = (state: PulseOperationalState) => PULSE_CLEANUPS.find((value) => value === state.cleanup_pending);

export const runPulsePendingCleanup = async () => {
  if (!findPendingCleanup(await redisGetPulseState())) {
    return;
  }
  await withPulsePushLock(async () => {
    // Read again under the lock: a configuration change may have replaced the pending cleanup in the meantime.
    const state = await redisGetPulseState();
    const pending = findPendingCleanup(state);
    if (pending) {
      await runPulseCleanup(pending, readPendingScope(state)).finally(refreshPulseStixPolicyNow);
    }
  });
};
// endregion

// XTM Hub enforces the reciprocity: a contributing platform without an accepted contribution within the grace period
// falls back to the preview until its next accepted contribution, whether a read answered contribution_required or the
// status of XTM Hub reported the lapse. The full statistics it held are removed first, so nothing stale passes for
// current: until they are, the platform is not marked lapsed and the next answer retries, like the next manager cycle.
// Serialized with the pages of the refresh, which stop once the access changed: none writes full statistics after it.
// Whether the platform is marked lapsed.
const markPulseContributionLapsed = async () => {
  if ((await redisGetPulseState()).contribution_lapsed === 'true') {
    return true;
  }
  return withPulsePushLock(async () => {
    if ((await redisGetPulseState()).contribution_lapsed === 'true') {
      return true;
    }
    if (!(await cleanupPulseData('network'))) {
      return false;
    }
    await redisSetPulseState({ contribution_lapsed: 'true', preview_refresh_at: undefined });
    logApp.info('[THREAT PULSE] XTM Hub requires a contribution, falling back to the preview until the next accepted contribution');
    return true;
  });
};

// Whether the answer was a lapse, now recorded.
export const handlePulseReadError = async (values: PulseSettingsValues, error: unknown) => {
  if (error instanceof PulseHubError && error.code === 'contribution_required' && isPulseContributing(values)) {
    return markPulseContributionLapsed();
  }
  return false;
};

export const toPulseUnavailableReason = (error: unknown): PulseUnavailableReason => {
  if (error instanceof PulseHubError) {
    switch (error.code) {
      case 'contribution_required':
        return PulseUnavailableReason.ContributionRequired;
      case 'rate_limited':
        return PulseUnavailableReason.RateLimited;
      case 'unauthenticated':
      case 'forbidden':
        return PulseUnavailableReason.NotRegistered;
      default:
        return PulseUnavailableReason.HubUnreachable;
    }
  }
  return PulseUnavailableReason.HubUnreachable;
};

export const getPulseSalt = async (platform: PulseHubPlatform, day: string): Promise<string> => {
  const cached = await redisGetPulseSalt(day);
  if (cached && isValidPulseHash(cached)) {
    return cached;
  }
  const { salt } = await xtmHubPulseClient.salt(platform, day);
  if (!isValidPulseHash(salt)) {
    throw new PulseHubError('unexpected', 'XTM Hub returned an invalid Threat Pulse salt');
  }
  await redisSetPulseSalt(day, salt);
  return salt;
};

// region status and settings
// Only preview documents carry a prevalence on a platform in preview.
const PULSE_PREVIEW_SIGNAL_FILTERS = {
  mode: FilterMode.And,
  filters: [{ key: ['pulse_prevalence'], values: [], operator: FilterOperator.NotNil }],
  filterGroups: [],
};

// preview_entities and preview_since hold what the preview pass found on every object, whatever its markings: the
// PulseStatus fields resolve them for the user who asks (resolvePulseStatusPreview).
export const getPulseStatus = async (context: AuthContext) => {
  const { values, state, access } = await loadPulseContext(context);
  const previewEntities = access === PulseAccess.Preview ? Number(state.preview_matched ?? 0) : 0;
  return {
    id: PULSE_STATUS_ID,
    enabled: isPulseContributing(values),
    mode: values.mode,
    access,
    readable: access === PulseAccess.Full,
    preview_entities: previewEntities,
    preview_since: previewEntities > 0 ? state.preview_since ?? null : null,
    sector_bucket: values.sectorBucket ?? null,
    region_bucket: values.regionBucket ?? null,
    scopes: values.scopes,
  };
};

interface PulseStatusPreview {
  preview_entities: number;
  preview_since?: string | null;
  scopes: string[];
}
const statusPreviews = new WeakMap<PulseStatusPreview, Promise<{ entities: number; since: string | null }>>();

// The objects carrying the preview signal among those the user can read, and since when the preview matched objects
// of the platform: counted once per status, and only when asked.
export const resolvePulseStatusPreview = (context: AuthContext, user: AuthUser, status: PulseStatusPreview) => {
  const known = statusPreviews.get(status);
  if (known) {
    return known;
  }
  const preview = (async () => {
    if (status.preview_entities <= 0) {
      return { entities: 0, since: null };
    }
    const entities = await elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { types: status.scopes, filters: PULSE_PREVIEW_SIGNAL_FILTERS });
    return { entities, since: entities > 0 ? status.preview_since ?? null : null };
  })();
  statusPreviews.set(status, preview);
  return preview;
};

const pulseStatusCacheKey = (platform: PulseHubPlatform) => `status:${platform.platformId}`;

const getPulseNetworkStatus = async (platform: PulseHubPlatform | null) => {
  const unreachable = {
    reachable: false,
    k_threshold: null,
    retention_months: null,
    contributors_bucket: null,
    read_access: null,
    last_contribution_day: null,
    contribution_status: null,
    read_access_until: null,
    contribution_window_days: null,
    contribution_grace_days: null,
  };
  if (!platform) {
    return unreachable;
  }
  try {
    const cacheKey = pulseStatusCacheKey(platform);
    let status = await redisGetPulseResponse<PulseHubStatus>(cacheKey);
    if (!status) {
      status = await xtmHubPulseClient.status(platform);
      await redisSetPulseResponse(cacheKey, status, STATUS_CACHE_TTL_SECONDS);
    }
    const contributionStatus = Object.values(PulseContributionStatus).find((value) => value === status.contribution_status) ?? null;
    return {
      reachable: true,
      ...status,
      contribution_status: contributionStatus,
      read_access_until: status.read_access_until ?? null,
      contribution_window_days: status.contribution_window_days ?? null,
      contribution_grace_days: status.contribution_grace_days ?? null,
    };
  } catch (error) {
    logApp.debug('[THREAT PULSE] Network status unavailable', { cause: error });
    return unreachable;
  }
};

export const getPulseSettings = async (context: AuthContext): Promise<PulseSettingsOutput> => {
  const { settings, values, platform, state, access: localAccess } = await loadPulseContext(context);
  const network = await getPulseNetworkStatus(platform);
  // XTM Hub reports the lapse of a quiet platform before any read of it answers contribution_required.
  const lapsed = localAccess === PulseAccess.Full && isPulseContributing(values) && network.contribution_status === PulseContributionStatus.Lapsed
    && await markPulseContributionLapsed();
  const access = lapsed ? PulseAccess.Preview : localAccess;
  const markings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const forcedMarkings = await getForcedExcludedMarkings(context);
  const suggested = await suggestPulseBuckets(context, settings);
  const stats = await redisGetPulseContributionStats(lastUtcDays(STATS_DAYS));
  const consentUser = values.consentUserId ? await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, values.consentUserId) : null;
  return {
    id: PULSE_SETTINGS_ID,
    mode: values.mode,
    access,
    enabled: isPulseContributing(values),
    readable: access === PulseAccess.Full,
    hub_registered: platform !== null,
    consent_version: PULSE_CONSENT_VERSION,
    consent_accepted_version: values.consentVersion ?? null,
    consent_date: values.consentDate ?? null,
    consent_user_name: consentUser?.name ?? null,
    scopes: values.scopes,
    available_scopes: PULSE_SCOPE_ENTITY_TYPES,
    excluded_markings: markings.filter((marking) => values.excludedMarkingIds.includes(marking.internal_id)),
    forced_excluded_markings: forcedMarkings,
    sector_bucket: values.sectorBucket ?? null,
    region_bucket: values.regionBucket ?? null,
    suggested_sector_bucket: suggested.sector,
    suggested_region_bucket: suggested.region,
    contribution: {
      last_push_at: state.last_push_at ?? null,
      last_refresh_at: state.last_refresh_at ?? null,
      last_error: state.last_error ?? null,
      total_records: stats.days.reduce((total, day) => total + day.records, 0),
      days: stats.days,
      by_type: stats.byType,
    },
    preview: {
      last_refresh_at: state.preview_refresh_at ?? null,
      digest_day: state.preview_digest_day ?? null,
      digest_items: Number(state.preview_digest_items ?? 0),
      matched_entities: Number(state.preview_matched ?? 0),
    },
    network,
  };
};

const describePulseMode = (mode: string) => {
  if (mode === PulseMode.ContributeAndRead) return 'contribution and full experience';
  if (mode === PulseMode.Preview) return 'preview, nothing sent';
  return 'off';
};

export const configurePulse = async (context: AuthContext, user: AuthUser, input: PulseConfigurationInput) => {
  const mode = input.mode as string;
  if (!PULSE_MODE_VALUES.includes(mode as typeof PULSE_MODE_VALUES[number])) {
    throw FunctionalError('Invalid Threat Pulse mode', { mode });
  }
  // Serialized with the pushes, with the pages of the nightly refresh and of the preview, and with the other
  // configuration changes: none of them runs halfway through the change, the ones after it read the new configuration
  // (generation), and the configuration it starts from is read inside the lock, from the database, so a concurrent
  // change is never overwritten with the values it replaced.
  const change = await withPulsePushLock(async () => {
    const { settings, values: current, platform } = await loadPulseContext(context, { fresh: true });
    const scopes = input.scopes ?? current.scopes;
    const invalidScopes = scopes.filter((scope) => !PULSE_SCOPE_ENTITY_TYPES.includes(scope));
    if (invalidScopes.length > 0) {
      throw FunctionalError('Threat Pulse scopes contain unsupported entity types', { invalidScopes });
    }
    const enabling = mode === PulseMode.ContributeAndRead;
    const wasContributing = isPulseContributing(current);
    if (mode !== PulseMode.Off && scopes.length === 0) {
      throw FunctionalError('Select at least one entity type for Threat Pulse');
    }
    if (enabling && !platform) {
      throw FunctionalError('Register the platform on XTM Hub before enabling the Threat Pulse contribution');
    }
    const markings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
    const requestedMarkings = input.excluded_markings ?? current.excludedMarkingIds;
    const excludedMarkingIds = requestedMarkings
      .map((markingId) => markings.find((marking) => marking.internal_id === markingId || marking.standard_id === markingId)?.internal_id);
    if (excludedMarkingIds.some((markingId) => !markingId)) {
      throw FunctionalError('Threat Pulse excluded markings contain unknown marking definitions');
    }
    const consentRequired = enabling && (!wasContributing || current.consentVersion !== PULSE_CONSENT_VERSION);
    if (consentRequired && input.consent_version !== PULSE_CONSENT_VERSION) {
      throw FunctionalError('The Threat Pulse consent must be accepted to enable the contribution', { required_version: PULSE_CONSENT_VERSION });
    }
    const sectorBucket = (input.sector_bucket ?? current.sectorBucket) as PulseSectorBucketValue | undefined;
    const regionBucket = (input.region_bucket ?? current.regionBucket) as PulseRegionBucketValue | undefined;
    const updates: Array<{ key: string; value: unknown[] }> = [
      { key: PULSE_SETTINGS_MODE, value: [mode] },
      { key: PULSE_SETTINGS_SCOPES, value: scopes },
      { key: PULSE_SETTINGS_EXCLUDED_MARKINGS, value: excludedMarkingIds as string[] },
      { key: PULSE_SETTINGS_SECTOR, value: sectorBucket ? [sectorBucket] : [] },
      { key: PULSE_SETTINGS_REGION, value: regionBucket ? [regionBucket] : [] },
    ];
    const consentDate = new Date();
    if (consentRequired) {
      updates.push(
        { key: PULSE_SETTINGS_CONSENT_VERSION, value: [PULSE_CONSENT_VERSION] },
        { key: PULSE_SETTINGS_CONSENT_DATE, value: [consentDate] },
        { key: PULSE_SETTINGS_CONSENT_USER, value: [user.id] },
      );
    }
    const narrowing = wasContributing && (!enabling
      || current.scopes.some((scope) => !scopes.includes(scope))
      || (excludedMarkingIds as string[]).some((markingId) => !current.excludedMarkingIds.includes(markingId)));
    const widening = wasContributing && enabling && (scopes.some((scope) => !current.scopes.includes(scope))
      || current.excludedMarkingIds.some((markingId) => !(excludedMarkingIds as string[]).includes(markingId)));
    const modeChanged = mode !== current.mode;
    if (narrowing) {
    // Before the settings change: from now on no batch built under the former, wider policy is sent, even when a
    // step below fails.
      await redisBumpPulsePolicyGeneration();
    }
    if (wasContributing && enabling) {
      // Before the settings change too: the activity of the window not collected yet stays under the narrowest settings
      // in force since it started, so that widening them never contributes what happened while they excluded it.
      const admission = await redisGetPulseAdmission();
      if (widening || admission) {
        const kept = admission?.scopes ?? current.scopes;
        await redisSetPulseAdmission({
          until: widening || !admission ? new Date().toISOString() : admission.until,
          scopes: kept.filter((scope) => current.scopes.includes(scope) && scopes.includes(scope)),
          excludedMarkingIds: Array.from(new Set([...(admission?.excludedMarkingIds ?? []), ...current.excludedMarkingIds, ...(excludedMarkingIds as string[])])),
        });
      }
    }
    if (enabling && !wasContributing) {
    // Before the settings change too, so that a failure leaves the platform not contributing: the contribution starts
    // at the consent, activity recorded before (a node whose settings cache had not seen the opt-out yet) is never
    // sent, nor the batches built under a former consent version still waiting in the outbox.
      await redisSetPulseCursor(consentDate.toISOString());
      await redisDiscardPulseAdmission();
      await redisDiscardPulseActivity(lastUtcDays(ACTIVITY_DAYS));
      await redisDiscardPulseOutbox();
    }
    // Before the settings change as well: a contribution cycle running under the former configuration records and
    // sends nothing more, and a failed bump leaves the settings untouched. A bump followed by a failed write is harmless.
    await redisBumpPulseConfigGeneration();
    await updateAttribute(context, user, settings.id, ENTITY_TYPE_SETTINGS, updates);
    if (!enabling) {
    // Nothing collected before the opt-out may leave afterwards.
      await redisDiscardPulseAdmission();
      await redisDiscardPulseOutbox();
      await redisDiscardPulseActivity(lastUtcDays(ACTIVITY_DAYS));
    } else if (narrowing) {
    // The batches not sent yet were built under the former, wider policy: they never leave (the policy generation
    // already refuses them; this frees them). Their activity was already acknowledged, so it is not contributed again;
    // the next run collects from there under the new policy.
      await redisDiscardPulseOutbox();
    }
    // The configuration stands whatever happens to these cleanups: a failed one is replayed by the next manager cycle.
    if (modeChanged && current.mode !== PulseMode.Off) {
    // The statistics of the previous mode never pass for those of the new one: the next cycle rebuilds them. Whatever
    // the connection to XTM Hub now, a mode that could write them is followed by a cleanup.
      await cleanupPulseData('network');
    } else if (!modeChanged && mode !== PulseMode.Off) {
    // The sector trends and the trending keys were read for the former sector or region: the stored statistics are
    // removed and the next cycle reads them again for the new one.
      const bucketsChanged = sectorBucket !== current.sectorBucket || regionBucket !== current.regionBucket;
      if (bucketsChanged && enabling) {
        await cleanupPulseData('network');
      } else {
      // A more restrictive configuration: the objects it takes out lose the statistics they received before. The
      // preview sends nothing, so its signal stays on every object in scope whatever the markings.
        const removedScopes = current.scopes.filter((scope) => !scopes.includes(scope));
        const addedExclusions = enabling ? (excludedMarkingIds as string[]).filter((markingId) => !current.excludedMarkingIds.includes(markingId)) : [];
        if (removedScopes.length > 0 || addedExclusions.length > 0) {
          await cleanupPulseData('scope', { entityTypes: removedScopes, markingIds: addedExclusions });
        }
      }
      if (bucketsChanged) {
        await redisSetPulseState({
          last_refresh_at: undefined,
          refresh_offset: undefined,
          preview_refresh_at: undefined,
          preview_offset: undefined,
          preview_scan_start: undefined,
        });
      }
    }
    if (modeChanged) {
      await redisSetPulseState({
        contribution_lapsed: undefined,
        contribution_accepted: undefined,
        last_refresh_at: undefined,
        refresh_offset: undefined,
        preview_refresh_at: undefined,
        preview_offset: undefined,
        preview_scan_start: undefined,
        preview_matched: undefined,
      });
      addThreatPulseModeChangeCount(mode as PulseMode);
    }
    return { settings, scopes, excludedMarkingIds, sectorBucket, regionBucket, consentRequired, enabling, wasContributing, modeChanged };
  });
  const { settings, scopes, excludedMarkingIds, sectorBucket, regionBucket, consentRequired, enabling, wasContributing, modeChanged } = change;
  let message = `updates the Threat Pulse configuration (${describePulseMode(mode)})`;
  if (enabling && !wasContributing) {
    message = `enables the Threat Pulse contribution (${describePulseMode(mode)}) and accepts the consent version \`${PULSE_CONSENT_VERSION}\``;
  } else if (wasContributing && !enabling) {
    message = `stops the Threat Pulse contribution (${describePulseMode(mode)})`;
  } else if (modeChanged && mode === PulseMode.Off) {
    message = 'turns Threat Pulse off';
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message,
    context_data: {
      id: settings.id,
      entity_type: ENTITY_TYPE_SETTINGS,
      input: {
        mode,
        scopes,
        excluded_markings: excludedMarkingIds,
        sector_bucket: sectorBucket,
        region_bucket: regionBucket,
        consent_version: consentRequired ? PULSE_CONSENT_VERSION : undefined,
      },
    },
  });
  const updatedSettings = await getSettings(context);
  await notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, updatedSettings, user);
  return getPulseSettings(context);
};
// endregion

// region contribution
interface PushOutcome {
  pushedRecords: number;
  error: PulseHubError | null;
  // The configuration changed during the cycle.
  stopped?: boolean;
}

// The pending batches, in order. They stay claimed in Redis until XTM Hub answers for each of them: a batch is settled
// once XTM Hub accepted it or refused it for good; on any other failure the push stops and the batches not settled yet
// stay claimed, so the next run claims them again. Nothing more leaves once the configuration changed since the cycle
// read it (generation).
const pushPulseOutbox = async (platform: PulseHubPlatform, oldestAcceptedDay: string, generation: string): Promise<PushOutcome> => {
  // Serialized with the purge and the configuration: a batch claimed before either never reaches XTM Hub after it.
  return withPulsePushLock(() => pushClaimedPulseOutbox(platform, oldestAcceptedDay, generation));
};

const pushClaimedPulseOutbox = async (platform: PulseHubPlatform, oldestAcceptedDay: string, generation: string): Promise<PushOutcome> => {
  const claimed = await redisClaimPulseOutbox();
  const policy = await redisGetPulsePolicyGeneration();
  // Past the accepted salt days, or built under a wider privacy policy than the current one.
  const dropped = claimed.filter((entry) => entry.batch.day < oldestAcceptedDay || (entry.policy ?? '0') !== policy);
  if (dropped.length > 0) {
    logApp.warn('[THREAT PULSE] Pending batches XTM Hub no longer accepts or built under a former policy are dropped', { dropped: dropped.length });
    for (let index = 0; index < dropped.length; index += 1) {
      await redisSettlePulseOutboxEntry(dropped[index], false);
    }
  }
  const retryable = claimed.filter((entry) => !dropped.includes(entry));
  let pushedRecords = 0;
  for (let index = 0; index < retryable.length; index += 1) {
    const entry = retryable[index];
    if ((await redisGetPulseConfigGeneration()) !== generation) {
      return { pushedRecords, error: null, stopped: true };
    }
    let accepted = 0;
    try {
      ({ accepted } = await xtmHubPulseClient.push(platform, entry.batch));
      pushedRecords += accepted;
    } catch (error) {
      const hubError = error instanceof PulseHubError ? error : new PulseHubError('unexpected', String(error));
      if (hubError.code !== 'bad_request') {
        return { pushedRecords, error: hubError };
      }
      logApp.error('[THREAT PULSE] XTM Hub refused a batch, it is dropped', { cause: hubError, records: entry.batch.records.length });
    }
    // The statistics count what XTM Hub accepted, once per batch.
    await redisSettlePulseOutboxEntry(entry, accepted > 0);
  }
  return { pushedRecords, error: null };
};

const storePulseKeys = async (context: AuthContext, entities: BasicStorePulseEntity[]) => {
  const updates: PulseDocumentUpdate[] = entities.flatMap((entity) => {
    const keys = computeStableKeys(entity);
    const stored = entity.pulse_keys ?? [];
    const changed = keys.length !== stored.length || keys.some((key) => !stored.includes(key));
    return changed ? [{ entity, doc: { pulse_keys: keys } }] : [];
  });
  await writePulseDocuments(context, updates);
};

// One hourly contribution: pending batches first, then the activity of the window since the last run.
// An accepted contribution opens the reads XTM Hub grants to contributors, or restores the ones it refused: the preview
// signal leaves room for the full refresh.
// The last error of a contribution: an answer of XTM Hub, or the code its manager step leaves when it throws. A
// successful contribution clears those only, never the code another step of the cycle left ("..._failed").
const recordContributionError = async (code: string | undefined) => {
  if (code) {
    await redisSetPulseState({ last_error: code });
    return;
  }
  const { last_error: current } = await redisGetPulseState();
  if (current && (!current.endsWith('_failed') || current === 'contribution_failed')) {
    await redisSetPulseState({ last_error: undefined });
  }
};

// Under the push lock and only while the configuration of the cycle is current: a purge, an unregistration or a
// configuration stored since the push removed the contribution state, and an earlier cycle never restores it.
const recordAcceptedContribution = async (platform: PulseHubPlatform, generation: string, pushedRecords: number, now: Date) => {
  if (pushedRecords <= 0) {
    return;
  }
  await withPulsePushLock(async () => {
    if ((await redisGetPulseConfigGeneration()) !== generation) {
      logApp.info('[THREAT PULSE] Configuration changed since the contribution was accepted, its state is left as is');
      return;
    }
    // The status XTM Hub returned before this contribution (lapsed, for instance) no longer applies.
    await redisDeletePulseResponse(pulseStatusCacheKey(platform));
    const state = await redisGetPulseState();
    const opening = state.contribution_accepted !== 'true' || state.contribution_lapsed === 'true';
    if (!opening) {
      await redisSetPulseState({ last_push_at: now.toISOString(), contribution_accepted: 'true' });
      return;
    }
    await redisSetPulseState({ last_push_at: now.toISOString() });
    // The preview signal goes before the full experience opens; a failed cleanup is replayed by the next manager cycle,
    // which opens it then.
    if (await cleanupPulseData('opening')) {
      logApp.info('[THREAT PULSE] Contribution accepted, the full experience is open');
    }
  });
};

interface PulseContributionCycle {
  values: PulseSettingsValues;
  platform: PulseHubPlatform;
  generation: string;
  policyGeneration: string;
  now: Date;
}

// The pending batches first, then the window since the last run; `accepted` receives what XTM Hub accepted, as soon as
// it accepted it.
const contributePulseCycle = async (context: AuthContext, cycle: PulseContributionCycle, accepted: (records: number) => void) => {
  const { values, platform, generation, policyGeneration, now } = cycle;
  const today = utcDay(now);
  const yesterday = previousUtcDay(today);
  const outboxOutcome = await pushPulseOutbox(platform, yesterday, generation);
  accepted(outboxOutcome.pushedRecords);
  if (outboxOutcome.error || outboxOutcome.stopped) {
    // Backpressure: no new window is collected while XTM Hub has not answered the pending batches.
    if (outboxOutcome.error) {
      await redisSetPulseState({ last_error: outboxOutcome.error.code });
    }
    return;
  }
  const cursor = await redisGetPulseCursor();
  // Never before the consent in force, whatever the cursor left by an earlier contribution says.
  const consentTime = new Date(values.consentDate ?? now).getTime();
  let since = new Date(Math.min(now.getTime(), Math.max(Date.parse(cursor ?? '') || consentTime, consentTime)));
  // XTM Hub serves the salts of today and yesterday only: older activity can never be contributed.
  const oldestAccepted = new Date(`${yesterday}T00:00:00.000Z`);
  if (since.getTime() < oldestAccepted.getTime()) {
    logApp.warn('[THREAT PULSE] Activity older than the accepted salt days is not contributed', { since: since.toISOString(), until: oldestAccepted.toISOString() });
    since = oldestAccepted;
  }
  // A window that starts before the last widening of the settings ends there and is collected under the former ones.
  const admission = await redisGetPulseAdmission();
  const admissionEnd = admission ? Date.parse(admission.until) : Number.NaN;
  const admitted = admission && since.getTime() < admissionEnd ? admission : null;
  const windowValues = admitted ? { ...values, scopes: admitted.scopes, excludedMarkingIds: admitted.excludedMarkingIds } : values;
  let until = new Date(Math.min(now.getTime(), since.getTime() + MAX_WINDOW_HOURS * 3600 * 1000, admitted ? admissionEnd : Number.POSITIVE_INFINITY));
  if (until.getTime() <= since.getTime()) {
    return;
  }
  // One budget of events per run for both sources: the activity kept in Redis (sightings seen again) is claimed first,
  // within half of it so that neither source starves the other, and the database window is bounded by the rest. Every
  // accepted day is taken, even with no budget left, so that what a failed run claimed is acknowledged with its batches.
  const acceptedDays = [yesterday, today];
  const externalByDay = new Map<string, PulseExternalActivity[]>();
  let externalEntries = 0;
  for (let index = 0; index < acceptedDays.length; index += 1) {
    const day = acceptedDays[index];
    const external = await redisTakePulseActivity(day, Math.ceil(MAX_EVENTS_PER_RUN / 2) - externalEntries);
    externalEntries += external.length;
    externalByDay.set(day, external);
  }
  const databaseBudget = Math.max(1, MAX_EVENTS_PER_RUN - externalEntries);
  const bounded = await boundPulseWindow(since, until, databaseBudget, (end) => countPulseActivity(context, PULSE_MANAGER_USER, windowValues.scopes, since, end));
  until = bounded.end;
  if (bounded.events > databaseBudget) {
    // Events of one millisecond cannot be told apart by the cursor: the window is cut at the budget and the cursor
    // moves past it, so a burst can never load more than one run may hold.
    logApp.warn('[THREAT PULSE] More events share one millisecond than one contribution reads, the rest of them is not contributed', {
      at: since.toISOString(),
      events: bounded.events,
      contributed: databaseBudget,
    });
  }
  // Each record carries the UTC day of its activity and is hashed with the salt of that day.
  const activityByDay = new Map<string, PulseActivity>();
  const windowSightings: PulseWindowSighting[] = [];
  const collectBudget: PulseCollectBudget = { remaining: databaseBudget };
  const segments = utcDaySegments(since, until);
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    const activity = await collectPulseActivity(context, PULSE_MANAGER_USER, windowValues.scopes, segment.since, segment.until, windowSightings, collectBudget);
    activityByDay.set(segment.day, activity);
  }
  externalByDay.forEach((external, day) => {
    if (external.length > 0) {
      activityByDay.set(day, mergePulseActivity(activityByDay.get(day) ?? new Map(), external));
    }
  });
  const policy = await buildPulseMarkingPolicy(context, windowValues);
  const buckets = getPulseBuckets(values);
  let records = 0;
  let excluded = 0;
  const windowItems: PulseOutboxItem[] = [];
  const days = Array.from(activityByDay.keys()).sort();
  for (let index = 0; index < days.length; index += 1) {
    const day = days[index];
    const activity = activityByDay.get(day) as PulseActivity;
    const entities = await loadPulseEntities(context, PULSE_MANAGER_USER, Array.from(activity.keys()));
    const aggregation = aggregatePulseActivity(activity, entities, policy, windowValues.scopes);
    records += aggregation.records.length;
    excluded += aggregation.excludedCount;
    if (aggregation.records.length > 0) {
      const items = buildPulseOutboxItems(aggregation.records, await getPulseSalt(platform, day), day, buckets);
      windowItems.push(...items.map((item) => ({ ...item, policy: policyGeneration })));
      await storePulseKeys(context, aggregation.contributedEntities);
    }
  }
  // Written ahead of any push, in one transaction: the batches of the window with their statistics, the cursor after
  // it and the acknowledgement of the activity taken from Redis. A run that stops before it sent nothing and the next
  // one collects the same window again; a run that stops after it leaves the batches in the outbox, sent by the next
  // run with the same identifiers, which XTM Hub counts once.
  if (!(await redisCommitPulseWindow(windowItems, until.toISOString(), acceptedDays, generation, windowSightings))) {
    // The configuration changed during the cycle: the window is collected again under the new one by the next run.
    logApp.info('[THREAT PULSE] Configuration changed during the contribution, the window is left to the next run');
    return;
  }
  const windowOutcome = await pushPulseOutbox(platform, yesterday, generation);
  accepted(windowOutcome.pushedRecords);
  await recordContributionError(windowOutcome.error?.code);
  logApp.info('[THREAT PULSE] Contribution done', {
    since: since.toISOString(),
    until: until.toISOString(),
    days,
    records,
    pushedRecords: outboxOutcome.pushedRecords + windowOutcome.pushedRecords,
    excluded,
  });
};

export const runPulseContribution = async (context: AuthContext) => {
  // Read before the settings, which come from the database: a configuration stored after this point stops the cycle
  // before it records or sends anything more.
  const generation = await redisGetPulseConfigGeneration();
  const policyGeneration = await redisGetPulsePolicyGeneration();
  const { values, platform } = await loadPulseContext(context, { fresh: true });
  if (!isPulseContributing(values) || !platform) {
    return { pushedRecords: 0 };
  }
  const now = new Date();
  let pushedRecords = 0;
  try {
    await contributePulseCycle(context, { values, platform, generation, policyGeneration, now }, (records) => {
      pushedRecords += records;
    });
  } finally {
    // Whatever stops the cycle after XTM Hub accepted records (an empty window, a failed collection), the accepted
    // contribution is recorded: it is what opens the full experience.
    await recordAcceptedContribution(platform, generation, pushedRecords, now);
    addThreatPulseRecordsCount(pushedRecords);
  }
  return { pushedRecords };
};

// endregion

// region read path
const hasPulseNetworkData = (entity: BasicStorePulseEntity) => {
  return (entity.pulse_information !== undefined && entity.pulse_information !== null)
    || (entity.pulse_prevalence !== undefined && entity.pulse_prevalence !== null);
};

// Read once per request, whatever the number of objects a list resolves the field for.
const pulseFieldPolicies = new WeakMap<AuthContext, Promise<PulseFieldPolicy>>();

const loadPulseFieldPolicy = (context: AuthContext) => {
  const known = pulseFieldPolicies.get(context);
  if (known) {
    return known;
  }
  const policy = (async () => {
    const { values, access } = await loadPulseContext(context);
    const markingPolicy = access === PulseAccess.Full ? await buildPulseMarkingPolicy(context, values) : null;
    return { access, scopes: values.scopes, markingPolicy };
  })();
  pulseFieldPolicies.set(context, policy);
  return policy;
};

export const resolvePulseField = async (context: AuthContext, entity: BasicStorePulseEntity) => {
  return visiblePulseInformation(entity, await loadPulseFieldPolicy(context));
};

// Filters, aggregations, date histograms and sorts read the network attributes straight from the index: they use only
// the values the field above shows, whatever a cleanup that failed or has not run yet left there.
registerAttributeQueryGate(PULSE_QUERYABLE_ATTRIBUTES, async (context) => pulseQueryClause(await loadPulseFieldPolicy(context)));
PULSE_SORTABLE_ATTRIBUTES.forEach((attribute) => {
  registerSortingOverride(attribute, async (context, _, orderMode) => pulseVisibleSort(await loadPulseFieldPolicy(context), attribute, orderMode));
});

const lookupKeys = async (platform: PulseHubPlatform, day: string, salt: string, objectType: PulseObjectType, keys: string[]) => {
  const results = new Map<string, PulseHubLookupResult>();
  for (let index = 0; index < keys.length; index += PULSE_MAX_LOOKUP_HASHES) {
    const chunk = keys.slice(index, index + PULSE_MAX_LOOKUP_HASHES);
    const hashes = chunk.map((key) => computeTransportHash(salt, key));
    const answers = await xtmHubPulseClient.lookup(platform, { day, object_type: objectType, hashes });
    addThreatPulseLookupsCount(hashes.length);
    const byHash = new Map(answers.map((answer) => [answer.hash, answer]));
    chunk.forEach((key, position) => {
      const answer = byHash.get(hashes[position]);
      if (answer) results.set(key, answer);
    });
  }
  return results;
};

export const refreshPulseEntities = async (context: AuthContext, platform: PulseHubPlatform, day: string, salt: string, entities: BasicStorePulseEntity[]) => {
  const keyed = entities.map((entity) => ({ entity, keys: computeStableKeys(entity) })).filter(({ keys }) => keys.length > 0);
  const keysByType = new Map<PulseObjectType, Set<string>>();
  keyed.forEach(({ entity, keys }) => {
    const objectType = PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[entity.entity_type];
    const set = keysByType.get(objectType) ?? new Set<string>();
    keys.forEach((key) => set.add(key));
    keysByType.set(objectType, set);
  });
  const resultsByType = new Map<PulseObjectType, Map<string, PulseHubLookupResult>>();
  const types = Array.from(keysByType.entries());
  for (let index = 0; index < types.length; index += 1) {
    const [objectType, keys] = types[index];
    resultsByType.set(objectType, await lookupKeys(platform, day, salt, objectType, Array.from(keys)));
  }
  const updatedAt = new Date();
  const updates = keyed.map(({ entity, keys }) => {
    const results = resultsByType.get(PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[entity.entity_type]) ?? new Map();
    const information = combinePulseLookups(keys.map((key) => results.get(key)).filter((result): result is PulseHubLookupResult => !!result));
    return { entity, doc: buildPulseDocument(keys, information, updatedAt) };
  });
  await writePulseDocuments(context, updates);
  return updates.length;
};

// A page of the nightly refresh or of the preview writes under the configuration and the access its pass started with:
// a configuration stored since, a lapse or the opening of the full experience stops the pass. Read under the lock.
const isPulsePassCurrent = async (generation: string, values: PulseSettingsValues, access: PulseAccess) => {
  if ((await redisGetPulseConfigGeneration()) !== generation) {
    return false;
  }
  return getPulseAccess(values, true, hasPulseReadAccess(await redisGetPulseState())) === access;
};

// Nightly refresh of the network information of every object in scope: the keys of an object that never contributed,
// matched or was read are computed here. A run handles up to REFRESH_MAX_ENTITIES objects and the next one goes on
// after them, starting over once the scope is covered, so that no object waits for ever on a large platform.
export const runPulseRefresh = async (context: AuthContext, force = false) => {
  // Read before the settings, which come from the database: each page checks it under the lock of the configuration.
  const generation = await redisGetPulseConfigGeneration();
  const { values, platform, state, access } = await loadPulseContext(context, { fresh: true });
  if (access !== PulseAccess.Full || !platform) {
    return 0;
  }
  if (!force && state.last_refresh_at && Date.now() - Date.parse(state.last_refresh_at) < REFRESH_INTERVAL_MS) {
    return 0;
  }
  const day = utcDay();
  const salt = await getPulseSalt(platform, day);
  const policy = await buildPulseMarkingPolicy(context, values);
  const offset = Math.max(0, Number(state.refresh_offset ?? 0) || 0);
  let scanned = 0;
  let handled = 0;
  let processed = 0;
  // Set once an eligible object past the cap was seen: the next run starts there. A run that fills the cap with the
  // last object of the scope reads one more page to know it, and the next run starts over.
  let remaining = false;
  let stopped = false;
  try {
    await fullEntitiesList<BasicStorePulseEntity>(context, PULSE_MANAGER_USER, values.scopes, {
      noFiltersChecking: true,
      callback: async (entities) => withPulsePushLock(async () => {
        if (!(await isPulsePassCurrent(generation, values, access))) {
          stopped = true;
          return false;
        }
        // An object that became restricted or received an excluded marking since its last refresh loses its statistics.
        const ineligible = entities.filter((entity) => !isPulseContributable(entity, policy, values.scopes) && hasPulseNetworkData(entity));
        await writePulseDocuments(context, ineligible.map((entity) => ({ entity, doc: PULSE_PREVIEW_CLEARED_DOCUMENT })));
        const eligible = entities.filter((entity) => isPulseContributable(entity, policy, values.scopes));
        const start = Math.max(0, offset - scanned);
        const room = REFRESH_MAX_ENTITIES - handled;
        scanned += eligible.length;
        remaining = eligible.length > start + room;
        const batch = eligible.slice(start, start + room);
        if (batch.length > 0) {
          handled += batch.length;
          processed += await refreshPulseEntities(context, platform, day, salt, batch);
        }
        return !remaining;
      }),
    });
  } catch (error) {
    await handlePulseReadError(values, error);
    throw error;
  }
  const covered = !remaining;
  // The checkpoint is written under the lock of its pages and only while the pass is current: a configuration change
  // or a purge that reset it after the last page always wins.
  const recorded = !stopped && await withPulsePushLock(async () => {
    if (!(await isPulsePassCurrent(generation, values, access))) {
      return false;
    }
    await redisSetPulseState({ last_refresh_at: new Date().toISOString(), refresh_offset: covered ? undefined : String(offset + handled) });
    return true;
  });
  if (!recorded) {
    logApp.info('[THREAT PULSE] Configuration or access changed during the network refresh, the next run reads under the new one');
    return processed;
  }
  logApp.info('[THREAT PULSE] Network information refreshed', { processed, offset, covered });
  return processed;
};

// The sector trending of the digest is the network trending when the platform discloses no sector.
const digestSectorBucket = (sectorBucket: PulseSectorBucketValue | null | undefined) => {
  return sectorBucket && sectorBucket !== PulseSectorBucket.Undisclosed ? sectorBucket : null;
};

// The trending of the digest covers every region when the platform discloses none.
const digestRegionBucket = (regionBucket: PulseRegionBucketValue | null | undefined) => {
  return regionBucket && regionBucket !== PulseRegionBucket.Undisclosed ? regionBucket : null;
};

const getHubDigest = async (
  platform: PulseHubPlatform,
  day: string,
  sectorBucket: PulseSectorBucketValue | null,
  regionBucket: PulseRegionBucketValue | null,
): Promise<PulseHubDigest> => {
  const cacheKey = `digest:${platform.platformId}:${day}:${sectorBucket ?? '*'}:${regionBucket ?? '*'}`;
  const cached = await redisGetPulseResponse<PulseHubDigest>(cacheKey);
  if (cached) {
    return cached;
  }
  const digest = await xtmHubPulseClient.digest(platform, { day, sector_bucket: sectorBucket, region_bucket: regionBucket });
  await redisSetPulseResponse(cacheKey, digest, RESPONSE_CACHE_TTL_SECONDS);
  return digest;
};

interface KeyedHubItem<T extends { hash: string; object_type: PulseObjectType }> {
  item: T;
  key: string;
}

const decodeHubItems = <T extends { hash: string; object_type: PulseObjectType }>(salt: string, items: T[]): Array<KeyedHubItem<T>> => {
  return items.filter((item) => isValidPulseHash(item.hash)).map((item) => ({ item, key: decodeTransportHash(salt, item.hash) }));
};

const sameKeys = (stored: string[] | undefined, keys: string[]) => {
  const current = stored ?? [];
  return current.length === keys.length && keys.every((key) => current.includes(key));
};

type PulsePreviewScanState = Pick<PulseOperationalState, 'preview_refresh_at' | 'preview_offset' | 'preview_scan_start' | 'preview_digest_day'>;

// Whether a preview pass runs now: once per refresh interval, and at every manager cycle while a scan has not covered
// the scope yet, so that a large platform is covered within the day of its digest.
export const isPulsePreviewPassDue = (state: PulsePreviewScanState, now: number, intervalMs: number, force = false) => {
  return force || state.preview_offset !== undefined || !state.preview_refresh_at || now - Date.parse(state.preview_refresh_at) >= intervalMs;
};

export interface PulsePreviewPassRange {
  offset: number;
  // Where the scan under this digest day started; a pass from before it stops there (until).
  scanStart: number;
  until: number | undefined;
}

// Where a preview pass starts: where the scan stopped, even when a new digest day began meanwhile, so that a scope
// larger than a day of passes is still covered. The new day then starts there: once the end of the scope is reached,
// the scan goes on from the start up to that point - an object never keeps the signal of an older digest once the
// scan covered the scope.
export const pulsePreviewPassRange = (state: PulsePreviewScanState, digestDay: string): PulsePreviewPassRange => {
  if (state.preview_offset === undefined) {
    return { offset: 0, scanStart: 0, until: undefined };
  }
  const offset = Math.max(0, Number(state.preview_offset) || 0);
  const scanStart = state.preview_digest_day === digestDay ? Math.max(0, Number(state.preview_scan_start ?? 0) || 0) : offset;
  return { offset, scanStart, until: offset < scanStart ? scanStart : undefined };
};

// The scan state after a pass that handled objects from the range, and reached its end or not.
export const pulsePreviewNextScan = (range: PulsePreviewPassRange, handled: number, reachedEnd: boolean) => {
  if (!reachedEnd) {
    return { preview_offset: String(range.offset + handled), preview_scan_start: range.scanStart > 0 ? String(range.scanStart) : undefined };
  }
  if (range.until === undefined && range.scanStart > 0) {
    return { preview_offset: '0', preview_scan_start: String(range.scanStart) };
  }
  return { preview_offset: undefined, preview_scan_start: undefined };
};

/**
 * The preview: zero outbound. The digest (the most prevalent published keys of the community, with their prevalence
 * and trend) is downloaded, the keys of the platform's own objects are computed locally and matched, and the coarse
 * signal is written on the matching objects without stream events. No contribution, lookup, trending or benchmark
 * request ever leaves the platform here; nothing leaves, so every object in scope is matched, whatever its markings.
 */
export const runPulsePreview = async (context: AuthContext, force = false) => {
  // As in the nightly refresh: each page checks the configuration generation and the access under the lock.
  const generation = await redisGetPulseConfigGeneration();
  const { values, platform, state, access } = await loadPulseContext(context, { fresh: true });
  if (access !== PulseAccess.Preview || !platform) {
    return 0;
  }
  if (!isPulsePreviewPassDue(state, Date.now(), REFRESH_INTERVAL_MS, force)) {
    return 0;
  }
  const day = utcDay();
  const salt = await getPulseSalt(platform, day);
  const digest = await getHubDigest(platform, day, digestSectorBucket(values.sectorBucket), digestRegionBucket(values.regionBucket));
  const signals = new Map<string, PulsePreviewSignal>();
  decodeHubItems(salt, digest.items).forEach(({ item, key }) => {
    signals.set(`${item.object_type}|${key}`, { prevalence: item.prevalence_bucket, trend: item.trend });
  });
  const trendingRefs = new Set(decodeHubItems(salt, digest.trending.items).map(({ item, key }) => `${item.object_type}|${key}`));
  const updatedAt = new Date();
  // A pass handles up to PREVIEW_MAX_ENTITIES objects; the next one goes on after them and starts over once the scope
  // is covered, so that every object in scope is matched on a large platform.
  const range = pulsePreviewPassRange(state, digest.day);
  const { offset, until } = range;
  if (state.preview_offset !== undefined && state.preview_digest_day !== digest.day) {
    logApp.info('[THREAT PULSE] A new digest day started before the preview scan covered the scope, the scan goes on with it', { from: state.preview_digest_day, to: digest.day, offset });
  }
  let scanned = 0;
  let handled = 0;
  let matched = 0;
  // Set once an object past the cap was seen, as in the nightly refresh.
  let remaining = false;
  // Set once a pass that started before the scan start of the digest day got there.
  let reachedUntil = false;
  let stopped = false;
  await fullEntitiesList<BasicStorePulseEntity>(context, PULSE_MANAGER_USER, values.scopes, {
    noFiltersChecking: true,
    callback: async (entities) => withPulsePushLock(async () => {
      if (!(await isPulsePassCurrent(generation, values, access))) {
        stopped = true;
        return false;
      }
      const start = Math.max(0, offset - scanned);
      const room = Math.min(PREVIEW_MAX_ENTITIES - handled, until === undefined ? Infinity : Math.max(0, until - offset - handled));
      scanned += entities.length;
      remaining = entities.length > start + room;
      const batch = entities.slice(start, start + room);
      handled += batch.length;
      reachedUntil = until !== undefined && offset + handled >= until;
      const updates: PulseDocumentUpdate[] = batch.flatMap((entity) => {
        const objectType = PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[entity.entity_type];
        const keys = computeStableKeys(entity);
        const refs = keys.map((key) => `${objectType}|${key}`);
        const signal = combinePulsePreviewSignals(refs.map((ref) => signals.get(ref)).filter((found): found is PulsePreviewSignal => !!found));
        if (signal) {
          matched += 1;
          return [{ entity, doc: buildPulsePreviewDocument(keys, signal, updatedAt) }];
        }
        // The keys of the trending objects held here let the trending widget name them.
        // Stored keys are kept current: an object renamed since never matches a trending entry through its former keys.
        const trending = refs.some((ref) => trendingRefs.has(ref));
        const storedKeys = (entity.pulse_keys ?? []).length > 0;
        const keysDoc = (trending || storedKeys) && !sameKeys(entity.pulse_keys, keys) ? { pulse_keys: keys } : {};
        if (entity.pulse_information?.preview) {
          return [{ entity, doc: { ...PULSE_PREVIEW_CLEARED_DOCUMENT, ...keysDoc } }];
        }
        return Object.keys(keysDoc).length > 0 ? [{ entity, doc: keysDoc }] : [];
      });
      await writePulseDocuments(context, updates);
      return !remaining && !reachedUntil;
    }),
  });
  if (stopped) {
    logApp.info('[THREAT PULSE] Configuration or access changed during the preview pass, the next pass reads under the new one');
    return matched;
  }
  const scan = pulsePreviewNextScan(range, handled, !remaining || reachedUntil);
  const covered = scan.preview_offset === undefined;
  // Every object the preview signal is on, whichever pass wrote it.
  const matchedTotal = await elCount(context, PULSE_MANAGER_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    types: values.scopes,
    filters: PULSE_PREVIEW_SIGNAL_FILTERS,
    noFiltersChecking: true,
  });
  // Under the lock of its pages and only while the pass is current, like the network refresh: a mode or bucket change
  // or a purge that reset the scan after the last page always wins.
  const recorded = await withPulsePushLock(async () => {
    if (!(await isPulsePassCurrent(generation, values, access))) {
      return false;
    }
    await redisSetPulseState({
      preview_refresh_at: updatedAt.toISOString(),
      ...scan,
      preview_digest_day: digest.day,
      preview_digest_items: String(digest.items.length),
      preview_matched: String(matchedTotal),
      preview_since: matchedTotal > 0 ? state.preview_since ?? updatedAt.toISOString() : state.preview_since,
    });
    return true;
  });
  if (!recorded) {
    logApp.info('[THREAT PULSE] Configuration or access changed during the preview pass, the next pass reads under the new one');
    return matched;
  }
  logApp.info('[THREAT PULSE] Preview refreshed from the digest', { digestItems: digest.items.length, offset, handled, matched, matchedTotal, covered });
  return matched;
};

// Lookups of entities opened at the same time are sent to XTM Hub in one batch per object type.
const lookupLoaders = new Map<string, DataLoader<string, PulseHubLookupResult | null>>();
const getLookupLoader = (platform: PulseHubPlatform, day: string, salt: string, objectType: PulseObjectType) => {
  // A new registration brings a new token: its loader never reuses the one holding the former token.
  const scope = `${platform.platformId}|${day}|${objectType}`;
  const loaderKey = `${scope}|${createHash('sha256').update(platform.platformToken).digest('hex').slice(0, 16)}`;
  const existing = lookupLoaders.get(loaderKey);
  if (existing) {
    return existing;
  }
  Array.from(lookupLoaders.keys())
    .filter((key) => !key.includes(`|${day}|`) || key.startsWith(`${scope}|`))
    .forEach((key) => lookupLoaders.delete(key));
  const loader = new DataLoader<string, PulseHubLookupResult | null>(async (keys) => {
    const results = await lookupKeys(platform, day, salt, objectType, [...keys]);
    return keys.map((key) => results.get(key) ?? null);
  }, { cache: false, maxBatchSize: PULSE_MAX_LOOKUP_HASHES, batchScheduleFn: (callback) => setTimeout(callback, 25) });
  lookupLoaders.set(loaderKey, loader);
  return loader;
};

interface PulseEntityAnswer {
  readable: boolean;
  unavailable_reason: PulseUnavailableReason | null;
  information: ReturnType<typeof toPulseInformationOutput>;
}

// What the stored state of an object answers under one configuration, or the platform to ask XTM Hub through.
const answerPulseEntityFromStore = async (
  context: AuthContext,
  entity: BasicStorePulseEntity,
  { values, platform, access }: Awaited<ReturnType<typeof loadPulseContext>>,
): Promise<PulseEntityAnswer | { lookup: PulseHubPlatform }> => {
  if (!PULSE_SCOPE_ENTITY_TYPES.includes(entity.entity_type) || !values.scopes.includes(entity.entity_type)) {
    return { readable: false, unavailable_reason: PulseUnavailableReason.OutOfScope, information: null };
  }
  if (access === PulseAccess.NotConnected || !platform) {
    return { readable: false, unavailable_reason: PulseUnavailableReason.NotRegistered, information: null };
  }
  if (access === PulseAccess.Off) {
    return { readable: false, unavailable_reason: PulseUnavailableReason.NotEnabled, information: null };
  }
  if (access === PulseAccess.Preview) {
    // The preview signal written by the last digest pass, if the object is among the most prevalent of the community.
    const information = isPulsePreviewDocument(entity) ? toPulseInformationOutput(entity) : null;
    return { readable: false, unavailable_reason: PulseUnavailableReason.ContributionRequired, information };
  }
  const policy = await buildPulseMarkingPolicy(context, values);
  if (!isPulseContributable(entity, policy, values.scopes)) {
    // Excluded since its last refresh: the statistics it still carries leave the filters, columns and exports now.
    if (hasPulseNetworkData(entity)) {
      await writePulseDocuments(context, [{ entity, doc: PULSE_PREVIEW_CLEARED_DOCUMENT }]);
    }
    return { readable: false, unavailable_reason: PulseUnavailableReason.Excluded, information: null };
  }
  const keys = computeStableKeys(entity);
  // The marker only vouches for the values looked up last: a pattern, name or alias changed since then is looked up again.
  if (entity.pulse_information?.updated_at && sameKeys(entity.pulse_keys, keys) && await redisGetPulseEntityLookup(entity.internal_id)) {
    return { readable: true, unavailable_reason: null, information: toPulseInformationOutput(entity) };
  }
  if (keys.length === 0) {
    return { readable: true, unavailable_reason: null, information: null };
  }
  return { lookup: platform };
};

interface PulseEntityLookupRequest {
  context: AuthContext;
  user: AuthUser;
  id: string;
}
type PulseEntityLookupAnswer = PulseEntityAnswer & { access: PulseAccess; sector_bucket: PulseSectorBucketValue | null };

// The lookups of objects opened at the same time share one pass under the lock of the configuration changes and of the
// cleanups, against the configuration stored now, like the manager passes: a lookup never sends the hash of an object a
// newer policy excludes, nor writes its statistics after the cleanup of that policy. Each object is read again for its
// reader: markings or access changed since the first read are the ones the policy judges. Their keys reach XTM Hub
// together, one request per object type.
const entityLookupLoader = new DataLoader<PulseEntityLookupRequest, PulseEntityLookupAnswer>((requests) => withPulsePushLock(async () => {
  const current = await loadPulseContext(requests[0].context, { fresh: true });
  const currentBase = { access: current.access, sector_bucket: current.values.sectorBucket ?? null };
  const day = utcDay();
  return Promise.all(requests.map(async ({ context, user, id }): Promise<PulseEntityLookupAnswer | Error> => {
    try {
      const reloaded = await storeLoadById<BasicStorePulseEntity>(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
      if (!reloaded) {
        return { ...currentBase, readable: false, unavailable_reason: PulseUnavailableReason.OutOfScope, information: null };
      }
      const answer = await answerPulseEntityFromStore(context, reloaded, current);
      if (!('lookup' in answer)) {
        return { ...currentBase, ...answer };
      }
      const keys = computeStableKeys(reloaded);
      const salt = await getPulseSalt(answer.lookup, day);
      const loader = getLookupLoader(answer.lookup, day, salt, PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[reloaded.entity_type]);
      const results = await Promise.all(keys.map((key) => loader.load(key)));
      const information = combinePulseLookups(results.filter((result): result is PulseHubLookupResult => !!result));
      const doc = buildPulseDocument(keys, information, new Date());
      await writePulseDocuments(context, [{ entity: reloaded, doc }]);
      await redisSetPulseEntityLookup(reloaded.internal_id, LOOKUP_CACHE_TTL_SECONDS);
      return { ...currentBase, readable: true, unavailable_reason: null, information: toPulseInformationOutput({ ...reloaded, ...doc } as BasicStorePulseEntity) };
    } catch (error) {
      // Fails the lookup of this object only.
      return error instanceof Error ? error : new Error(String(error));
    }
  }));
}), { cache: false, batchScheduleFn: (callback) => setTimeout(callback, 25) });

export const getPulseEntityInformation = async (context: AuthContext, user: AuthUser, id: string) => {
  const pulse = await loadPulseContext(context);
  const entity = await storeLoadById<BasicStorePulseEntity>(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const base = { id, access: pulse.access, sector_bucket: pulse.values.sectorBucket ?? null };
  if (!entity) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.OutOfScope, information: null };
  }
  const stored = await answerPulseEntityFromStore(context, entity, pulse);
  if (!('lookup' in stored)) {
    return { ...base, ...stored };
  }
  try {
    return { ...base, ...await entityLookupLoader.load({ context, user, id }) };
  } catch (error) {
    logApp.warn('[THREAT PULSE] Entity lookup failed', { cause: error, entityId: entity.internal_id });
    await handlePulseReadError(pulse.values, error);
    const reason = toPulseUnavailableReason(error);
    if (reason === PulseUnavailableReason.ContributionRequired) {
      return { ...base, access: PulseAccess.Preview, readable: false, unavailable_reason: reason, information: null };
    }
    return { ...base, readable: true, unavailable_reason: reason, information: toPulseInformationOutput(entity) };
  }
};

const resolveLocalEntitiesByKeys = async (context: AuthContext, user: AuthUser, entityTypes: string[], keys: string[]) => {
  if (keys.length === 0 || entityTypes.length === 0) {
    return [];
  }
  const filters: FilterGroup = {
    mode: FilterMode.And,
    filters: [{ key: ['pulse_keys'], values: keys, operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  return fullEntitiesList<BasicStorePulseEntity>(context, user, entityTypes, { filters, noFiltersChecking: true });
};

// Trending hashes are matched against the keys of the local entities the user can read: only what the platform holds
// can be resolved.
export const matchHubItemsToEntities = <T extends { hash: string; object_type: PulseObjectType }>(
  keyedItems: Array<KeyedHubItem<T>>,
  entities: BasicStorePulseEntity[],
  score: (item: T) => number,
) => {
  return entities.flatMap((entity) => {
    const candidates = keyedItems.filter(({ item, key }) => PULSE_ENTITY_TYPE_BY_OBJECT_TYPE[item.object_type] === entity.entity_type
      && (entity.pulse_keys ?? []).includes(key));
    if (candidates.length === 0) {
      return [];
    }
    const [best] = candidates.sort((a, b) => score(b.item) - score(a.item));
    return [{ entity, item: best.item }];
  });
};

export const getHubTrending = async (
  platform: PulseHubPlatform,
  input: { period: PulsePeriodValue; sector_bucket: PulseSectorBucketValue | null; region_bucket: PulseRegionBucketValue | null; object_types: PulseObjectType[]; first: number },
): Promise<PulseHubTrendingResult> => {
  const day = utcDay();
  const cacheKey = `trending:${platform.platformId}:${day}:${input.period}:${input.sector_bucket ?? '*'}:${input.region_bucket ?? '*'}:${[...input.object_types].sort().join(',')}:${input.first}`;
  const cached = await redisGetPulseResponse<PulseHubTrendingResult>(cacheKey);
  if (cached) {
    return cached;
  }
  const result = await xtmHubPulseClient.trending(platform, { day, ...input, object_types: input.object_types.length > 0 ? input.object_types : null });
  await redisSetPulseResponse(cacheKey, result, RESPONSE_CACHE_TTL_SECONDS);
  return result;
};

// The community data of a contributing platform covers the objects it contributes only: an object excluded since its
// last refresh (scope, excluded marking, restriction) is left out, as its own Threat Pulse fields are, although the
// preview pass may have kept its keys.
const contributedEntities = async (context: AuthContext, values: PulseSettingsValues, entities: BasicStorePulseEntity[]) => {
  if (entities.length === 0) {
    return entities;
  }
  const policy = await buildPulseMarkingPolicy(context, values);
  return entities.filter((entity) => isPulseContributable(entity, policy, values.scopes));
};

export const resolveTrendingEntries = async (
  context: AuthContext,
  user: AuthUser,
  platform: PulseHubPlatform,
  result: PulseHubTrendingResult,
  values: PulseSettingsValues,
  entityTypes: string[],
) => {
  const salt = await getPulseSalt(platform, result.day);
  const keyedItems = decodeHubItems<PulseHubTrendingItem>(salt, result.items);
  const entities = await contributedEntities(context, values, await resolveLocalEntitiesByKeys(context, user, entityTypes, keyedItems.map(({ key }) => key)));
  return matchHubItemsToEntities(keyedItems, entities, (item) => item.growth)
    .sort((a, b) => b.item.growth - a.item.growth)
    .map(({ entity, item }) => ({
      entity,
      object_type: entity.entity_type,
      platforms_bucket: item.platforms_bucket,
      prevalence: item.prevalence_bucket,
      trend: item.trend,
      growth: item.growth,
      first_seen_network: toDayDate(item.first_seen_network),
    }));
};

export const getPulseTrending = async (context: AuthContext, user: AuthUser, args: {
  period: PulsePeriodValue;
  sector_bucket?: PulseSectorBucketValue | null;
  region_bucket?: PulseRegionBucketValue | null;
  entity_types?: string[] | null;
  first?: number | null;
  include_preview?: boolean | null;
}) => {
  const { values, platform, access } = await loadPulseContext(context);
  const sectorBucket = args.sector_bucket ?? values.sectorBucket ?? null;
  const regionBucket = args.region_bucket ?? null;
  const base = {
    readable: false,
    preview: false,
    day: null,
    period: args.period,
    sector_bucket: sectorBucket,
    region_bucket: regionBucket,
    network_items_count: 0,
    locked_count: 0,
    entries: [],
  };
  if (access === PulseAccess.NotConnected || !platform) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotRegistered };
  }
  if (access === PulseAccess.Off) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotEnabled };
  }
  const entityTypes = (args.entity_types ?? values.scopes).filter((type) => values.scopes.includes(type));
  if (access === PulseAccess.Preview) {
    if (!args.include_preview) {
      return { ...base, unavailable_reason: PulseUnavailableReason.ContributionRequired };
    }
    // The digest of the preview pass, which stored the keys of the trending objects held here, unless another region is asked.
    const previewRegion = digestRegionBucket(args.region_bucket ?? values.regionBucket);
    return getPulsePreviewTrending(context, user, platform, digestSectorBucket(sectorBucket), previewRegion, entityTypes);
  }
  const first = Math.min(MAX_TRENDING_SIZE, Math.max(1, args.first ?? DEFAULT_TRENDING_SIZE));
  try {
    const result = await getHubTrending(platform, {
      period: args.period,
      sector_bucket: sectorBucket,
      region_bucket: regionBucket,
      object_types: entityTypes.map((type) => PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[type]),
      first,
    });
    const entries = await resolveTrendingEntries(context, user, platform, result, values, entityTypes);
    return {
      readable: true,
      preview: false,
      unavailable_reason: null,
      day: result.day,
      period: result.period,
      sector_bucket: result.sector_bucket,
      region_bucket: result.region_bucket,
      network_items_count: result.items.length,
      locked_count: 0,
      entries,
    };
  } catch (error) {
    logApp.warn('[THREAT PULSE] Trending unavailable', { cause: error });
    await handlePulseReadError(values, error);
    return { ...base, unavailable_reason: toPulseUnavailableReason(error) };
  }
};

// The preview trending of the digest: its first ranks, named when the platform holds them, the next ones counted.
const getPulsePreviewTrending = async (
  context: AuthContext,
  user: AuthUser,
  platform: PulseHubPlatform,
  sectorBucket: PulseSectorBucketValue | null,
  regionBucket: PulseRegionBucketValue | null,
  entityTypes: string[],
) => {
  const day = utcDay();
  const base = {
    readable: false,
    preview: true,
    day: null,
    period: PulsePeriod.Last_7Days,
    sector_bucket: sectorBucket,
    region_bucket: regionBucket,
    network_items_count: 0,
    locked_count: 0,
    entries: [],
  };
  try {
    const salt = await getPulseSalt(platform, day);
    const digest = await getHubDigest(platform, day, sectorBucket, regionBucket);
    const keyedItems = decodeHubItems(salt, digest.trending.items);
    const entities = await resolveLocalEntitiesByKeys(context, user, entityTypes, keyedItems.map(({ key }) => key));
    const entries = matchHubItemsToEntities(keyedItems, entities, (item) => -item.rank)
      .sort((a, b) => a.item.rank - b.item.rank)
      .map(({ entity, item }) => ({
        entity,
        object_type: entity.entity_type,
        rank: item.rank,
        platforms_bucket: null,
        prevalence: item.prevalence_bucket,
        trend: item.trend,
        growth: null,
        first_seen_network: null,
      }));
    return {
      ...base,
      readable: true,
      unavailable_reason: null,
      day: digest.day,
      period: digest.trending.period,
      sector_bucket: digest.sector_bucket ?? null,
      region_bucket: digest.region_bucket ?? null,
      network_items_count: digest.trending.items.length,
      locked_count: digest.trending.locked_count,
      entries,
    };
  } catch (error) {
    logApp.warn('[THREAT PULSE] Preview trending unavailable', { cause: error });
    return { ...base, unavailable_reason: toPulseUnavailableReason(error) };
  }
};

export const getPulseBenchmark = async (context: AuthContext, user: AuthUser, args: { period: PulsePeriodValue }) => {
  const { values, platform, access } = await loadPulseContext(context);
  const base = {
    readable: false,
    period: args.period,
    sector_bucket: values.sectorBucket ?? null,
    region_bucket: values.regionBucket ?? null,
    sector_platforms_bucket: null,
    metrics: [],
    entries: [],
  };
  // The access state first: a platform in preview gets the locked benchmark tiles, whatever its edition.
  if (access === PulseAccess.NotConnected || !platform) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotRegistered };
  }
  if (access === PulseAccess.Off) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotEnabled };
  }
  if (access === PulseAccess.Preview) {
    return { ...base, unavailable_reason: PulseUnavailableReason.ContributionRequired };
  }
  if (!await isEnterpriseEdition(context)) {
    return { ...base, unavailable_reason: PulseUnavailableReason.EnterpriseEditionRequired };
  }
  try {
    const day = utcDay();
    // The sector and region of the answer are those configured when it was read: a change reads it again.
    const cacheKey = `benchmark:${platform.platformId}:${day}:${args.period}:${values.sectorBucket ?? '*'}:${values.regionBucket ?? '*'}`;
    let result = await redisGetPulseResponse<Awaited<ReturnType<typeof xtmHubPulseClient.benchmark>>>(cacheKey);
    if (!result) {
      result = await xtmHubPulseClient.benchmark(platform, { day, period: args.period });
      await redisSetPulseResponse(cacheKey, result, RESPONSE_CACHE_TTL_SECONDS);
    }
    const salt = await getPulseSalt(platform, day);
    const keyedItems = decodeHubItems(salt, result.top_items);
    const entityTypes = values.scopes;
    const entities = await contributedEntities(context, values, await resolveLocalEntitiesByKeys(context, user, entityTypes, keyedItems.map(({ key }) => key)));
    const entries = matchHubItemsToEntities(keyedItems, entities, (item) => item.ratio)
      .sort((a, b) => b.item.ratio - a.item.ratio)
      .map(({ entity, item }) => ({
        entity,
        object_type: entity.entity_type,
        platform_count: item.platform_count,
        sector_median: item.sector_median,
        ratio: item.ratio,
      }));
    return {
      readable: true,
      unavailable_reason: null,
      period: result.period,
      sector_bucket: result.sector_bucket,
      region_bucket: result.region_bucket,
      sector_platforms_bucket: result.sector_platforms_bucket,
      metrics: result.metrics.map((metric) => ({
        object_type: PULSE_ENTITY_TYPE_BY_OBJECT_TYPE[metric.object_type] ?? metric.object_type,
        event_kind: metric.event_kind,
        // The activity of the platform in its current sector, the operand of the comparison with the sector median: the
        // count shown next to the median and the ratio are the same figure.
        platform_count: metric.sector_platform_count,
        sector_median: metric.sector_median,
        network_median: metric.network_median,
        ratio: metric.sector_median && metric.sector_median > 0 ? metric.sector_platform_count / metric.sector_median : null,
      })),
      entries,
    };
  } catch (error) {
    logApp.warn('[THREAT PULSE] Benchmark unavailable', { cause: error });
    await handlePulseReadError(values, error);
    return { ...base, unavailable_reason: toPulseUnavailableReason(error) };
  }
};
// endregion

// region usage telemetry of the preview surfaces
// Counted only while the platform is in preview, whatever the client says: these are the impressions and calls to
// action of the preview.
export const recordPulseTelemetry = async (context: AuthContext, event: PulseTelemetryEvent, surface: PulseSurface) => {
  const { access } = await loadPulseContext(context);
  if (access !== PulseAccess.Preview) {
    return false;
  }
  addThreatPulsePreviewEventCount(event, surface);
  return true;
};
// endregion

// The platform leaves XTM Hub. *unregister* writes the settings: it runs under the push lock once the generations
// moved, so no push and no page of the nightly refresh or of the preview runs halfway through it, and none started
// before it sends or writes afterwards. A contributing platform goes back to the preview in the same write: contributing
// again, after a new registration, takes a renewed consent. The community data written for the platform and the state
// of its contribution go with the registration, so nothing stale passes for current.
export const unregisterFromPulse = async (
  context: AuthContext,
  unregister: (pulseUpdates: Array<{ key: string; value: unknown[] }>) => Promise<void>,
) => {
  await withPulsePushLock(async () => {
    await redisBumpPulsePolicyGeneration();
    await redisBumpPulseConfigGeneration();
    const { values } = await loadPulseContext(context, { fresh: true });
    await unregister(isPulseContributing(values) ? [{ key: PULSE_SETTINGS_MODE, value: [PulseMode.Preview] }] : []);
    // The unregistration stands whatever happens to the cleanup: the generations already stop every cycle started
    // before it, and a failed cleanup is replayed by the next manager cycle without any registration.
    await cleanupPulseData('registration');
  });
};

// region purge
export const purgePulseContributions = async (context: AuthContext, user: AuthUser) => {
  const { settings, platform } = await loadPulseContext(context);
  if (!platform) {
    throw FunctionalError('Register the platform on XTM Hub to purge its Threat Pulse contributions');
  }
  // Serialized with the pushes and with the pages of the nightly refresh and of the preview, cleanup included: none of
  // them runs during the purge, and a cycle started before it records, sends and writes nothing after it (generation).
  // The pending work goes with the purge.
  const result = await withPulsePushLock(async () => {
    await redisBumpPulseConfigGeneration();
    const { access } = await loadPulseContext(context);
    let purged: { success: boolean; deleted_records: number };
    try {
      purged = await xtmHubPulseClient.purge(platform);
    } catch (error) {
      throw FunctionalError('XTM Hub could not purge the Threat Pulse contributions, retry later', { reason: toPulseUnavailableReason(error) });
    }
    if (!purged.success) {
      // The contributions are still on XTM Hub: the local tracking stays, and nothing is audited as purged.
      logApp.warn('[THREAT PULSE] XTM Hub did not purge the Threat Pulse contributions');
      return purged;
    }
    await redisClearPulseContributionState(lastUtcDays(STATS_DAYS + 1));
    await redisSetPulseCursor(new Date().toISOString());
    // XTM Hub no longer holds a contribution of the platform: the full reads wait for the next accepted one.
    await redisSetPulseState({ contribution_accepted: undefined, contribution_lapsed: undefined, last_push_at: undefined, last_refresh_at: undefined, refresh_offset: undefined });
    if (access === PulseAccess.Full) {
      // The purge stands: a failed cleanup of the full statistics is replayed by the next manager cycle.
      await cleanupPulseData('network');
    }
    return purged;
  });
  if (!result.success) {
    return result;
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `purges every Threat Pulse contribution of the platform on XTM Hub (${result.deleted_records} records)`,
    context_data: { id: settings.id, entity_type: ENTITY_TYPE_SETTINGS, input: { deleted_records: result.deleted_records } },
  });
  return result;
};
// endregion
