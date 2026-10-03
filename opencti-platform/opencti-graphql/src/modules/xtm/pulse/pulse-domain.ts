import DataLoader from 'dataloader';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import type { BasicStoreEntity, StoreMarkingDefinition } from '../../../types/store';
import conf, { BUS_TOPICS, logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../database/cache';
import { updateAttribute } from '../../../database/middleware';
import { fullEntitiesList, internalLoadById, storeLoadById } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../schema/stixMetaObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import { PULSE_MANAGER_USER, SYSTEM_USER } from '../../../utils/access';
import { publishUserAction } from '../../../listener/UserActionListener';
import { isEnterpriseEdition } from '../../../enterprise-edition/ee';
import { getSettings } from '../../../domain/settings';
import { addThreatPulseLookupsCount, addThreatPulseRecordsCount } from '../../../manager/telemetryManager';
import { FilterMode, FilterOperator, type FilterGroup, type PulseConfigurationInput, PulseMode, PulseUnavailableReason } from '../../../generated/graphql';
import { PulseHubError, type PulseHubPlatform, xtmHubPulseClient } from '../hub/xtm-hub-pulse-client';
import { aggregatePulseActivity, buildPulseBatches, collectPulseActivity, countPulseActivity, loadPulseEntities, mergePulseActivity } from './pulse-collector';
import { computeStableKeys, computeTransportHash, decodeTransportHash, isValidPulseHash } from './pulse-hashing';
import {
  buildPulseDocument,
  clearPulseNetworkInformation,
  combinePulseLookups,
  type PulseDocumentUpdate,
  toPulseInformationOutput,
  writePulseDocuments,
} from './pulse-information';
import {
  buildPulseMarkingPolicy,
  getForcedExcludedMarkings,
  getPulseBuckets,
  getPulseHubPlatform,
  isPulseContributable,
  isPulseContributing,
  isPulseReading,
  readPulseSettings,
  suggestPulseBuckets,
} from './pulse-settings';
import {
  redisAddPulseActivity,
  redisAddPulseContributionStats,
  redisClearPulseContributionState,
  redisGetPulseContributionStats,
  redisGetPulseCursor,
  redisGetPulseEntityLookup,
  redisGetPulseResponse,
  redisGetPulseSalt,
  redisGetPulseState,
  redisPopPulseOutbox,
  redisPushPulseOutbox,
  redisSetPulseCursor,
  redisSetPulseEntityLookup,
  redisSetPulseResponse,
  redisSetPulseSalt,
  redisSetPulseState,
  redisTakePulseActivity,
} from './pulse-cache';
import {
  type BasicStorePulseEntity,
  PULSE_CONSENT_VERSION,
  PULSE_ENTITY_TYPE_BY_OBJECT_TYPE,
  PULSE_EVENT_KINDS,
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
  type PulseBatch,
  type PulseEventKind,
  type PulseHubLookupResult,
  type PulseHubStatus,
  type PulseHubTrendingItem,
  type PulseHubTrendingResult,
  type PulseObjectType,
  type PulsePeriodValue,
  type PulseRegionBucketValue,
  type PulseSectorBucketValue,
  type PulseSettingsOutput,
} from './pulse-types';

const ONE_DAY_MS = 24 * 3600 * 1000;
const LOOKUP_CACHE_TTL_SECONDS = conf.get('pulse_manager:lookup_cache_ttl_seconds') ?? 6 * 3600;
const RESPONSE_CACHE_TTL_SECONDS = conf.get('pulse_manager:response_cache_ttl_seconds') ?? 900;
const STATUS_CACHE_TTL_SECONDS = 300;
const MAX_WINDOW_HOURS = conf.get('pulse_manager:max_window_hours') ?? 24;
const MAX_EVENTS_PER_RUN = conf.get('pulse_manager:max_events_per_run') ?? 100000;
const REFRESH_INTERVAL_MS = conf.get('pulse_manager:refresh_interval') ?? ONE_DAY_MS;
const REFRESH_MAX_ENTITIES = conf.get('pulse_manager:refresh_max_entities') ?? 200000;
const STATS_DAYS = 30;
const DEFAULT_TRENDING_SIZE = 50;
const MAX_TRENDING_SIZE = 200;

// region time helpers
export const utcDay = (date = new Date()) => date.toISOString().slice(0, 10);

export const previousUtcDay = (day: string) => utcDay(new Date(Date.parse(`${day}T00:00:00.000Z`) - ONE_DAY_MS));

export const lastUtcDays = (count: number, from = new Date()) => {
  return Array.from({ length: count }, (_, index) => utcDay(new Date(from.getTime() - (count - 1 - index) * ONE_DAY_MS)));
};
// endregion

const loadPulseContext = async (context: AuthContext) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const values = readPulseSettings(settings);
  return { settings, values, platform: getPulseHubPlatform(settings) };
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
export const getPulseStatus = async (context: AuthContext) => {
  const { values, platform } = await loadPulseContext(context);
  return {
    id: PULSE_STATUS_ID,
    enabled: isPulseContributing(values),
    mode: values.mode,
    readable: isPulseReading(values) && platform !== null,
    sector_bucket: values.sectorBucket ?? null,
    region_bucket: values.regionBucket ?? null,
    scopes: values.scopes,
  };
};

const getPulseNetworkStatus = async (platform: PulseHubPlatform | null) => {
  const unreachable = { reachable: false, k_threshold: null, retention_months: null, contributors_bucket: null, read_access: null, last_contribution_day: null };
  if (!platform) {
    return unreachable;
  }
  try {
    const cacheKey = `status:${platform.platformId}`;
    let status = await redisGetPulseResponse<PulseHubStatus>(cacheKey);
    if (!status) {
      status = await xtmHubPulseClient.status(platform);
      await redisSetPulseResponse(cacheKey, status, STATUS_CACHE_TTL_SECONDS);
    }
    return { reachable: true, ...status };
  } catch (error) {
    logApp.debug('[THREAT PULSE] Network status unavailable', { cause: error });
    return unreachable;
  }
};

export const getPulseSettings = async (context: AuthContext): Promise<PulseSettingsOutput> => {
  const { settings, values, platform } = await loadPulseContext(context);
  const markings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const forcedMarkings = await getForcedExcludedMarkings(context);
  const suggested = await suggestPulseBuckets(context, settings);
  const state = await redisGetPulseState();
  const stats = await redisGetPulseContributionStats(lastUtcDays(STATS_DAYS));
  const consentUser = values.consentUserId ? await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, values.consentUserId) : null;
  return {
    id: PULSE_SETTINGS_ID,
    mode: values.mode,
    enabled: isPulseContributing(values),
    readable: isPulseReading(values) && platform !== null,
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
    network: await getPulseNetworkStatus(platform),
  };
};

const describePulseMode = (mode: string) => {
  if (mode === PulseMode.ContributeAndRead) return 'contribution and reading';
  if (mode === PulseMode.Contribute) return 'contribution only';
  return 'off';
};

export const configurePulse = async (context: AuthContext, user: AuthUser, input: PulseConfigurationInput) => {
  const { settings, values: current, platform } = await loadPulseContext(context);
  const mode = input.mode as string;
  if (!PULSE_MODE_VALUES.includes(mode as typeof PULSE_MODE_VALUES[number])) {
    throw FunctionalError('Invalid Threat Pulse mode', { mode });
  }
  const scopes = input.scopes ?? current.scopes;
  const invalidScopes = scopes.filter((scope) => !PULSE_SCOPE_ENTITY_TYPES.includes(scope));
  if (invalidScopes.length > 0) {
    throw FunctionalError('Threat Pulse scopes contain unsupported entity types', { invalidScopes });
  }
  const enabling = mode !== PulseMode.Off;
  if (enabling && scopes.length === 0) {
    throw FunctionalError('Select at least one entity type to contribute to Threat Pulse');
  }
  if (enabling && !platform) {
    throw FunctionalError('Register the platform on XTM Hub before enabling Threat Pulse');
  }
  const markings = await getEntitiesListFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const requestedMarkings = input.excluded_markings ?? current.excludedMarkingIds;
  const excludedMarkingIds = requestedMarkings.map((markingId) => markings.find((marking) => marking.internal_id === markingId || marking.standard_id === markingId)?.internal_id);
  if (excludedMarkingIds.some((markingId) => !markingId)) {
    throw FunctionalError('Threat Pulse excluded markings contain unknown marking definitions');
  }
  const consentRequired = enabling && (current.mode === PulseMode.Off || current.consentVersion !== PULSE_CONSENT_VERSION);
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
  if (consentRequired) {
    updates.push(
      { key: PULSE_SETTINGS_CONSENT_VERSION, value: [PULSE_CONSENT_VERSION] },
      { key: PULSE_SETTINGS_CONSENT_DATE, value: [new Date()] },
      { key: PULSE_SETTINGS_CONSENT_USER, value: [user.id] },
    );
  }
  await updateAttribute(context, user, settings.id, ENTITY_TYPE_SETTINGS, updates);
  if (enabling && current.mode === PulseMode.Off) {
    await redisSetPulseCursor(new Date().toISOString());
  }
  if (!enabling) {
    // Nothing collected before the opt-out may leave afterwards.
    await redisPopPulseOutbox();
    await redisTakePulseActivity();
  }
  if (isPulseReading(current) && mode !== PulseMode.ContributeAndRead) {
    await clearPulseNetworkInformation();
  }
  let message = `updates the Threat Pulse configuration (${describePulseMode(mode)})`;
  if (current.mode === PulseMode.Off && enabling) {
    message = `enables Threat Pulse (${describePulseMode(mode)}) and accepts the consent version \`${PULSE_CONSENT_VERSION}\``;
  } else if (current.mode !== PulseMode.Off && !enabling) {
    message = 'disables Threat Pulse';
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
}

const pushPulseBatches = async (platform: PulseHubPlatform, batches: PulseBatch[]): Promise<PushOutcome> => {
  let pushedRecords = 0;
  for (let index = 0; index < batches.length; index += 1) {
    const batch = batches[index];
    try {
      const { accepted } = await xtmHubPulseClient.push(platform, batch);
      pushedRecords += accepted;
    } catch (error) {
      const hubError = error instanceof PulseHubError ? error : new PulseHubError('unexpected', String(error));
      if (hubError.code === 'bad_request') {
        logApp.error('[THREAT PULSE] XTM Hub refused a batch, it is dropped', { cause: hubError, records: batch.records.length });
      } else {
        await redisPushPulseOutbox(batches.slice(index));
        return { pushedRecords, error: hubError };
      }
    }
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
export const runPulseContribution = async (context: AuthContext) => {
  const { values, platform } = await loadPulseContext(context);
  if (!isPulseContributing(values) || !platform) {
    return { pushedRecords: 0 };
  }
  const now = new Date();
  const today = utcDay(now);
  const yesterday = previousUtcDay(today);
  let pushedRecords = 0;
  const pending = await redisPopPulseOutbox();
  const retryable = pending.filter((batch) => batch.day >= yesterday);
  if (pending.length > retryable.length) {
    logApp.warn('[THREAT PULSE] Pending batches older than the accepted salt days are dropped', { dropped: pending.length - retryable.length });
  }
  const outboxOutcome = await pushPulseBatches(platform, retryable);
  pushedRecords += outboxOutcome.pushedRecords;
  if (outboxOutcome.error) {
    await redisSetPulseState({ last_error: outboxOutcome.error.code });
    addThreatPulseRecordsCount(pushedRecords);
    return { pushedRecords };
  }
  const salt = await getPulseSalt(platform, today);
  const cursor = await redisGetPulseCursor();
  const since = new Date(Math.min(now.getTime(), Date.parse(cursor ?? '') || new Date(values.consentDate ?? now).getTime()));
  let until = new Date(Math.min(now.getTime(), since.getTime() + MAX_WINDOW_HOURS * 3600 * 1000));
  if (until.getTime() <= since.getTime()) {
    return { pushedRecords };
  }
  const activityCount = await countPulseActivity(context, PULSE_MANAGER_USER, values.scopes, since, until);
  if (activityCount > MAX_EVENTS_PER_RUN) {
    const span = Math.max(60 * 1000, Math.floor(((until.getTime() - since.getTime()) * MAX_EVENTS_PER_RUN) / activityCount));
    until = new Date(since.getTime() + span);
  }
  const activity = await collectPulseActivity(context, PULSE_MANAGER_USER, values.scopes, since, until);
  mergePulseActivity(activity, await redisTakePulseActivity());
  const entities = await loadPulseEntities(context, PULSE_MANAGER_USER, Array.from(activity.keys()));
  const policy = await buildPulseMarkingPolicy(context, values);
  const aggregation = aggregatePulseActivity(activity, entities, policy, values.scopes);
  let lastError: string | undefined;
  if (aggregation.records.length > 0) {
    const batches = buildPulseBatches(aggregation.records, salt, today, getPulseBuckets(values));
    const outcome = await pushPulseBatches(platform, batches);
    pushedRecords += outcome.pushedRecords;
    lastError = outcome.error?.code;
    await storePulseKeys(context, aggregation.contributedEntities);
    await redisAddPulseContributionStats(today, outcome.pushedRecords, aggregation.contributedEntities.length, aggregation.recordsByEntityType);
  }
  await redisSetPulseCursor(until.toISOString());
  await redisSetPulseState({ last_push_at: now.toISOString(), last_error: lastError });
  addThreatPulseRecordsCount(pushedRecords);
  logApp.info('[THREAT PULSE] Contribution done', {
    since: since.toISOString(),
    until: until.toISOString(),
    records: aggregation.records.length,
    pushedRecords,
    excluded: aggregation.excludedCount,
  });
  return { pushedRecords };
};

export const recordPulseActivity = async (context: AuthContext, entityId: string, eventKind: PulseEventKind, count = 1) => {
  if (!PULSE_EVENT_KINDS.includes(eventKind)) {
    throw FunctionalError('Unsupported Threat Pulse event kind', { eventKind });
  }
  const { values } = await loadPulseContext(context);
  if (!isPulseContributing(values)) {
    return false;
  }
  await redisAddPulseActivity(entityId, eventKind, Math.max(1, Math.floor(count)));
  return true;
};
// endregion

// region read path
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

const keysExistFilter: FilterGroup = {
  mode: FilterMode.And,
  filters: [{ key: ['pulse_keys'], values: [], operator: FilterOperator.NotNil }],
  filterGroups: [],
};

// Nightly refresh of the network information of every object that already has Threat Pulse keys.
export const runPulseRefresh = async (context: AuthContext, force = false) => {
  const { values, platform } = await loadPulseContext(context);
  if (!isPulseReading(values) || !platform) {
    return 0;
  }
  const state = await redisGetPulseState();
  if (!force && state.last_refresh_at && Date.now() - Date.parse(state.last_refresh_at) < REFRESH_INTERVAL_MS) {
    return 0;
  }
  const day = utcDay();
  const salt = await getPulseSalt(platform, day);
  const policy = await buildPulseMarkingPolicy(context, values);
  let processed = 0;
  await fullEntitiesList<BasicStorePulseEntity>(context, PULSE_MANAGER_USER, values.scopes, {
    filters: keysExistFilter,
    noFiltersChecking: true,
    callback: async (entities) => {
      const eligible = entities.filter((entity) => isPulseContributable(entity, policy, values.scopes));
      processed += await refreshPulseEntities(context, platform, day, salt, eligible);
      return processed < REFRESH_MAX_ENTITIES;
    },
  });
  await redisSetPulseState({ last_refresh_at: new Date().toISOString() });
  logApp.info('[THREAT PULSE] Network information refreshed', { processed });
  return processed;
};

// Lookups of entities opened at the same time are sent to XTM Hub in one batch per object type.
const lookupLoaders = new Map<string, DataLoader<string, PulseHubLookupResult | null>>();
const getLookupLoader = (platform: PulseHubPlatform, day: string, salt: string, objectType: PulseObjectType) => {
  const loaderKey = `${platform.platformId}|${day}|${objectType}`;
  const existing = lookupLoaders.get(loaderKey);
  if (existing) {
    return existing;
  }
  Array.from(lookupLoaders.keys()).filter((key) => !key.includes(`|${day}|`)).forEach((key) => lookupLoaders.delete(key));
  const loader = new DataLoader<string, PulseHubLookupResult | null>(async (keys) => {
    const results = await lookupKeys(platform, day, salt, objectType, [...keys]);
    return keys.map((key) => results.get(key) ?? null);
  }, { cache: false, maxBatchSize: PULSE_MAX_LOOKUP_HASHES, batchScheduleFn: (callback) => setTimeout(callback, 25) });
  lookupLoaders.set(loaderKey, loader);
  return loader;
};

export const getPulseEntityInformation = async (context: AuthContext, user: AuthUser, id: string) => {
  const { values, platform } = await loadPulseContext(context);
  const entity = await storeLoadById<BasicStorePulseEntity>(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const base = { id, sector_bucket: values.sectorBucket ?? null, information: null };
  if (!entity || !PULSE_SCOPE_ENTITY_TYPES.includes(entity.entity_type) || !values.scopes.includes(entity.entity_type)) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.OutOfScope };
  }
  if (!isPulseReading(values)) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.NotEnabled };
  }
  if (!platform) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.NotRegistered };
  }
  const policy = await buildPulseMarkingPolicy(context, values);
  if (!isPulseContributable(entity, policy, values.scopes)) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.Excluded };
  }
  if (entity.pulse_information?.updated_at && await redisGetPulseEntityLookup(entity.internal_id)) {
    return { ...base, readable: true, unavailable_reason: null, information: toPulseInformationOutput(entity) };
  }
  const keys = computeStableKeys(entity);
  if (keys.length === 0) {
    return { ...base, readable: true, unavailable_reason: null };
  }
  try {
    const day = utcDay();
    const salt = await getPulseSalt(platform, day);
    const loader = getLookupLoader(platform, day, salt, PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[entity.entity_type]);
    const results = await Promise.all(keys.map((key) => loader.load(key)));
    const information = combinePulseLookups(results.filter((result): result is PulseHubLookupResult => !!result));
    const doc = buildPulseDocument(keys, information, new Date());
    await writePulseDocuments(context, [{ entity, doc }]);
    await redisSetPulseEntityLookup(entity.internal_id, LOOKUP_CACHE_TTL_SECONDS);
    return { ...base, readable: true, unavailable_reason: null, information: toPulseInformationOutput({ ...entity, ...doc } as BasicStorePulseEntity) };
  } catch (error) {
    logApp.warn('[THREAT PULSE] Entity lookup failed', { cause: error, entityId: entity.internal_id });
    return { ...base, readable: true, unavailable_reason: toPulseUnavailableReason(error), information: toPulseInformationOutput(entity) };
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

interface KeyedHubItem<T extends { hash: string; object_type: PulseObjectType }> {
  item: T;
  key: string;
}

const decodeHubItems = <T extends { hash: string; object_type: PulseObjectType }>(salt: string, items: T[]): Array<KeyedHubItem<T>> => {
  return items.filter((item) => isValidPulseHash(item.hash)).map((item) => ({ item, key: decodeTransportHash(salt, item.hash) }));
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

export const resolveTrendingEntries = async (context: AuthContext, user: AuthUser, platform: PulseHubPlatform, result: PulseHubTrendingResult, entityTypes: string[]) => {
  const salt = await getPulseSalt(platform, result.day);
  const keyedItems = decodeHubItems<PulseHubTrendingItem>(salt, result.items);
  const entities = await resolveLocalEntitiesByKeys(context, user, entityTypes, keyedItems.map(({ key }) => key));
  return matchHubItemsToEntities(keyedItems, entities, (item) => item.growth)
    .sort((a, b) => b.item.growth - a.item.growth)
    .map(({ entity, item }) => ({
      entity,
      object_type: entity.entity_type,
      platforms_bucket: item.platforms_bucket,
      prevalence: item.prevalence_bucket,
      trend: item.trend,
      growth: item.growth,
      first_seen_network: `${item.first_seen_network}T00:00:00.000Z`,
    }));
};

export const getPulseTrending = async (context: AuthContext, user: AuthUser, args: {
  period: PulsePeriodValue;
  sector_bucket?: PulseSectorBucketValue | null;
  region_bucket?: PulseRegionBucketValue | null;
  entity_types?: string[] | null;
  first?: number | null;
}) => {
  const { values, platform } = await loadPulseContext(context);
  const sectorBucket = args.sector_bucket ?? values.sectorBucket ?? null;
  const regionBucket = args.region_bucket ?? null;
  const base = { readable: false, day: null, period: args.period, sector_bucket: sectorBucket, region_bucket: regionBucket, network_items_count: 0, entries: [] };
  if (!isPulseReading(values)) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotEnabled };
  }
  if (!platform) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotRegistered };
  }
  const entityTypes = (args.entity_types ?? values.scopes).filter((type) => values.scopes.includes(type));
  const first = Math.min(MAX_TRENDING_SIZE, Math.max(1, args.first ?? DEFAULT_TRENDING_SIZE));
  try {
    const result = await getHubTrending(platform, {
      period: args.period,
      sector_bucket: sectorBucket,
      region_bucket: regionBucket,
      object_types: entityTypes.map((type) => PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[type]),
      first,
    });
    const entries = await resolveTrendingEntries(context, user, platform, result, entityTypes);
    return {
      readable: true,
      unavailable_reason: null,
      day: result.day,
      period: result.period,
      sector_bucket: result.sector_bucket,
      region_bucket: result.region_bucket,
      network_items_count: result.items.length,
      entries,
    };
  } catch (error) {
    logApp.warn('[THREAT PULSE] Trending unavailable', { cause: error });
    return { ...base, unavailable_reason: toPulseUnavailableReason(error) };
  }
};

export const getPulseBenchmark = async (context: AuthContext, user: AuthUser, args: { period: PulsePeriodValue }) => {
  const { values, platform } = await loadPulseContext(context);
  const base = {
    readable: false,
    period: args.period,
    sector_bucket: values.sectorBucket ?? null,
    region_bucket: values.regionBucket ?? null,
    sector_platforms_bucket: null,
    metrics: [],
    entries: [],
  };
  if (!await isEnterpriseEdition(context)) {
    return { ...base, unavailable_reason: PulseUnavailableReason.EnterpriseEditionRequired };
  }
  if (!isPulseReading(values)) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotEnabled };
  }
  if (!platform) {
    return { ...base, unavailable_reason: PulseUnavailableReason.NotRegistered };
  }
  try {
    const day = utcDay();
    const cacheKey = `benchmark:${platform.platformId}:${day}:${args.period}`;
    let result = await redisGetPulseResponse<Awaited<ReturnType<typeof xtmHubPulseClient.benchmark>>>(cacheKey);
    if (!result) {
      result = await xtmHubPulseClient.benchmark(platform, { day, period: args.period });
      await redisSetPulseResponse(cacheKey, result, RESPONSE_CACHE_TTL_SECONDS);
    }
    const salt = await getPulseSalt(platform, day);
    const keyedItems = decodeHubItems(salt, result.top_items);
    const entityTypes = values.scopes;
    const entities = await resolveLocalEntitiesByKeys(context, user, entityTypes, keyedItems.map(({ key }) => key));
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
        platform_count: metric.platform_count,
        sector_median: metric.sector_median,
        network_median: metric.network_median,
        ratio: metric.sector_median && metric.sector_median > 0 ? metric.platform_count / metric.sector_median : null,
      })),
      entries,
    };
  } catch (error) {
    logApp.warn('[THREAT PULSE] Benchmark unavailable', { cause: error });
    return { ...base, unavailable_reason: toPulseUnavailableReason(error) };
  }
};
// endregion

// region purge
export const purgePulseContributions = async (context: AuthContext, user: AuthUser) => {
  const { settings, platform } = await loadPulseContext(context);
  if (!platform) {
    throw FunctionalError('Register the platform on XTM Hub to purge its Threat Pulse contributions');
  }
  let result: { success: boolean; deleted_records: number };
  try {
    result = await xtmHubPulseClient.purge(platform);
  } catch (error) {
    throw FunctionalError('XTM Hub could not purge the Threat Pulse contributions, retry later', { reason: toPulseUnavailableReason(error) });
  }
  await redisClearPulseContributionState(lastUtcDays(STATS_DAYS + 1));
  await redisSetPulseCursor(new Date().toISOString());
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
