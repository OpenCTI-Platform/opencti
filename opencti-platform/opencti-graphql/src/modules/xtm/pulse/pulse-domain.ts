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
import { PULSE_MANAGER_USER, SYSTEM_USER } from '../../../utils/access';
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
  buildPulseOutboxItems,
  collectPulseActivity,
  countPulseActivity,
  loadPulseEntities,
  mergePulseActivity,
  type PulseActivity,
} from './pulse-collector';
import { computeStableKeys, computeTransportHash, decodeTransportHash, isValidPulseHash } from './pulse-hashing';
import {
  buildPulseDocument,
  buildPulsePreviewDocument,
  clearPulseNetworkInformation,
  combinePulseLookups,
  combinePulsePreviewSignals,
  PULSE_PREVIEW_CLEARED_DOCUMENT,
  type PulseDocumentUpdate,
  type PulsePreviewSignal,
  toPulseInformationOutput,
  writePulseDocuments,
} from './pulse-information';
import {
  buildPulseMarkingPolicy,
  getForcedExcludedMarkings,
  getPulseAccess,
  hasPulseReadAccess,
  getPulseBuckets,
  getPulseHubPlatform,
  isPulseContributable,
  isPulseContributing,
  readPulseSettings,
  suggestPulseBuckets,
} from './pulse-settings';
import {
  redisAddPulseActivity,
  redisClaimPulseOutbox,
  redisBumpPulseConfigGeneration,
  redisBumpPulsePolicyGeneration,
  redisCommitPulseWindow,
  redisDiscardPulseActivity,
  redisDiscardPulseOutbox,
  redisClearPulseContributionState,
  redisGetPulseContributionStats,
  redisGetPulseConfigGeneration,
  redisGetPulsePolicyGeneration,
  redisGetPulseCursor,
  redisGetPulseEntityLookup,
  redisGetPulseResponse,
  redisGetPulseSalt,
  redisGetPulseState,
  redisSettlePulseOutboxEntry,
  redisSetPulseCursor,
  redisSetPulseEntityLookup,
  redisSetPulseResponse,
  redisSetPulseSalt,
  redisSetPulseState,
  redisTakePulseActivity,
  type PulseOperationalState,
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
  type PulseEventKind,
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

// XTM Hub enforces the reciprocity: a contributing platform it answers contribution_required to (no accepted
// contribution within the grace period) falls back to the preview until its next accepted contribution. The full
// statistics it held are removed, so nothing stale passes for current.
const handlePulseReadError = async (values: PulseSettingsValues, error: unknown) => {
  if (!(error instanceof PulseHubError) || error.code !== 'contribution_required' || !isPulseContributing(values)) {
    return;
  }
  const state = await redisGetPulseState();
  if (state.contribution_lapsed === 'true') {
    return;
  }
  await redisSetPulseState({ contribution_lapsed: 'true', preview_refresh_at: undefined });
  await clearPulseNetworkInformation();
  logApp.info('[THREAT PULSE] XTM Hub requires a contribution, falling back to the preview until the next accepted contribution');
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
    const cacheKey = `status:${platform.platformId}`;
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
  const { settings, values, platform, state, access } = await loadPulseContext(context);
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
    network: await getPulseNetworkStatus(platform),
  };
};

const describePulseMode = (mode: string) => {
  if (mode === PulseMode.ContributeAndRead) return 'contribution and full experience';
  if (mode === PulseMode.Preview) return 'preview, nothing sent';
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
  const excludedMarkingIds = requestedMarkings.map((markingId) => markings.find((marking) => marking.internal_id === markingId || marking.standard_id === markingId)?.internal_id);
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
  if (consentRequired) {
    updates.push(
      { key: PULSE_SETTINGS_CONSENT_VERSION, value: [PULSE_CONSENT_VERSION] },
      { key: PULSE_SETTINGS_CONSENT_DATE, value: [new Date()] },
      { key: PULSE_SETTINGS_CONSENT_USER, value: [user.id] },
    );
  }
  const narrowing = wasContributing && (!enabling
    || current.scopes.some((scope) => !scopes.includes(scope))
    || (excludedMarkingIds as string[]).some((markingId) => !current.excludedMarkingIds.includes(markingId)));
  if (narrowing) {
    // Before the settings change: from now on no batch built under the former, wider policy is sent, even when a
    // step below fails.
    await redisBumpPulsePolicyGeneration();
  }
  await updateAttribute(context, user, settings.id, ENTITY_TYPE_SETTINGS, updates);
  // A contribution cycle running under the former configuration records and sends nothing more from now on.
  await redisBumpPulseConfigGeneration();
  if (enabling && !wasContributing) {
    // The contribution starts now: activity recorded before (a node whose settings cache had not seen the opt-out yet,
    // a hunt) is never sent.
    await redisSetPulseCursor(new Date().toISOString());
    await redisDiscardPulseActivity(lastUtcDays(ACTIVITY_DAYS));
  }
  if (!enabling) {
    // Nothing collected before the opt-out may leave afterwards.
    await redisDiscardPulseOutbox();
    await redisDiscardPulseActivity(lastUtcDays(ACTIVITY_DAYS));
  } else if (narrowing) {
    // The batches not sent yet were built under the former, wider policy: they never leave (the policy generation
    // already refuses them; this frees them). Their activity was already acknowledged, so it is not contributed again;
    // the next run collects from there under the new policy.
    await redisDiscardPulseOutbox();
  }
  const modeChanged = mode !== current.mode;
  if (modeChanged && current.mode !== PulseMode.Off) {
    // The statistics of the previous mode never pass for those of the new one: the next cycle rebuilds them. Whatever
    // the connection to XTM Hub now, a mode that could write them is followed by a cleanup.
    await clearPulseNetworkInformation();
  } else if (!modeChanged && mode !== PulseMode.Off) {
    // The sector trends and the trending keys were read for the former sector or region: the stored statistics are
    // removed and the next cycle reads them again for the new one.
    const bucketsChanged = sectorBucket !== current.sectorBucket || regionBucket !== current.regionBucket;
    if (bucketsChanged && enabling) {
      await clearPulseNetworkInformation();
    } else {
      // A more restrictive configuration: the objects it takes out lose the statistics they received before. The
      // preview sends nothing, so its signal stays on every object in scope whatever the markings.
      const removedScopes = current.scopes.filter((scope) => !scopes.includes(scope));
      const addedExclusions = enabling ? (excludedMarkingIds as string[]).filter((markingId) => !current.excludedMarkingIds.includes(markingId)) : [];
      await clearPulseNetworkInformation({ entityTypes: removedScopes, markingIds: addedExclusions });
    }
    if (bucketsChanged) {
      await redisSetPulseState({ last_refresh_at: undefined, refresh_offset: undefined, preview_refresh_at: undefined, preview_offset: undefined });
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
      preview_matched: undefined,
    });
    addThreatPulseModeChangeCount(mode as PulseMode);
  }
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
  // Serialized with the purge: a batch claimed before a purge never reaches XTM Hub after it.
  const lock = await lockResources([PULSE_PUSH_LOCK_KEY]);
  try {
    return await pushClaimedPulseOutbox(platform, oldestAcceptedDay, generation);
  } finally {
    await lock.unlock();
  }
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
const recordAcceptedContribution = async (state: PulseOperationalState, pushedRecords: number, now: Date) => {
  if (pushedRecords <= 0) {
    return;
  }
  const opening = state.contribution_accepted !== 'true' || state.contribution_lapsed === 'true';
  await redisSetPulseState({
    last_push_at: now.toISOString(),
    contribution_accepted: 'true',
    ...(opening ? { contribution_lapsed: undefined, last_refresh_at: undefined, preview_matched: undefined } : {}),
  });
  if (opening) {
    await clearPulseNetworkInformation();
    logApp.info('[THREAT PULSE] Contribution accepted, the full experience is open');
  }
};

export const runPulseContribution = async (context: AuthContext) => {
  // Read before the settings, which come from the database: a configuration stored after this point stops the cycle
  // before it records or sends anything more.
  const generation = await redisGetPulseConfigGeneration();
  const policyGeneration = await redisGetPulsePolicyGeneration();
  const { values, platform, state } = await loadPulseContext(context, { fresh: true });
  if (!isPulseContributing(values) || !platform) {
    return { pushedRecords: 0 };
  }
  const now = new Date();
  const today = utcDay(now);
  const yesterday = previousUtcDay(today);
  let pushedRecords = 0;
  const outboxOutcome = await pushPulseOutbox(platform, yesterday, generation);
  pushedRecords += outboxOutcome.pushedRecords;
  if (outboxOutcome.error || outboxOutcome.stopped) {
    // Backpressure: no new window is collected while XTM Hub has not answered the pending batches.
    if (outboxOutcome.error) {
      await redisSetPulseState({ last_error: outboxOutcome.error.code });
    }
    await recordAcceptedContribution(state, pushedRecords, now);
    addThreatPulseRecordsCount(pushedRecords);
    return { pushedRecords };
  }
  const cursor = await redisGetPulseCursor();
  let since = new Date(Math.min(now.getTime(), Date.parse(cursor ?? '') || new Date(values.consentDate ?? now).getTime()));
  // XTM Hub serves the salts of today and yesterday only: older activity can never be contributed.
  const oldestAccepted = new Date(`${yesterday}T00:00:00.000Z`);
  if (since.getTime() < oldestAccepted.getTime()) {
    logApp.warn('[THREAT PULSE] Activity older than the accepted salt days is not contributed', { since: since.toISOString(), until: oldestAccepted.toISOString() });
    since = oldestAccepted;
  }
  let until = new Date(Math.min(now.getTime(), since.getTime() + MAX_WINDOW_HOURS * 3600 * 1000));
  if (until.getTime() <= since.getTime()) {
    return { pushedRecords };
  }
  const activityCount = await countPulseActivity(context, PULSE_MANAGER_USER, values.scopes, since, until);
  if (activityCount > MAX_EVENTS_PER_RUN) {
    const span = Math.max(60 * 1000, Math.floor(((until.getTime() - since.getTime()) * MAX_EVENTS_PER_RUN) / activityCount));
    until = new Date(since.getTime() + span);
  }
  // Each record carries the UTC day of its activity and is hashed with the salt of that day.
  const activityByDay = new Map<string, PulseActivity>();
  const segments = utcDaySegments(since, until);
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    activityByDay.set(segment.day, await collectPulseActivity(context, PULSE_MANAGER_USER, values.scopes, segment.since, segment.until));
  }
  const acceptedDays = [yesterday, today];
  for (let index = 0; index < acceptedDays.length; index += 1) {
    const day = acceptedDays[index];
    const external = await redisTakePulseActivity(day);
    if (external.length > 0) {
      activityByDay.set(day, mergePulseActivity(activityByDay.get(day) ?? new Map(), external));
    }
  }
  const policy = await buildPulseMarkingPolicy(context, values);
  const buckets = getPulseBuckets(values);
  let records = 0;
  let excluded = 0;
  const windowItems: PulseOutboxItem[] = [];
  const days = Array.from(activityByDay.keys()).sort();
  for (let index = 0; index < days.length; index += 1) {
    const day = days[index];
    const activity = activityByDay.get(day) as PulseActivity;
    const entities = await loadPulseEntities(context, PULSE_MANAGER_USER, Array.from(activity.keys()));
    const aggregation = aggregatePulseActivity(activity, entities, policy, values.scopes);
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
  if (!(await redisCommitPulseWindow(windowItems, until.toISOString(), acceptedDays, generation))) {
    // The configuration changed during the cycle: the window is collected again under the new one by the next run.
    logApp.info('[THREAT PULSE] Configuration changed during the contribution, the window is left to the next run');
    await recordAcceptedContribution(state, pushedRecords, now);
    addThreatPulseRecordsCount(pushedRecords);
    return { pushedRecords };
  }
  const windowOutcome = await pushPulseOutbox(platform, yesterday, generation);
  pushedRecords += windowOutcome.pushedRecords;
  await redisSetPulseState({ last_error: windowOutcome.error?.code });
  await recordAcceptedContribution(state, pushedRecords, now);
  addThreatPulseRecordsCount(pushedRecords);
  logApp.info('[THREAT PULSE] Contribution done', {
    since: since.toISOString(),
    until: until.toISOString(),
    days,
    records,
    pushedRecords,
    excluded,
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
  await redisAddPulseActivity(utcDay(), entityId, eventKind, Math.max(1, Math.floor(count)));
  return true;
};
// endregion

// region read path
const hasPulseNetworkData = (entity: BasicStorePulseEntity) => {
  return (entity.pulse_information !== undefined && entity.pulse_information !== null)
    || (entity.pulse_prevalence !== undefined && entity.pulse_prevalence !== null);
};

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

// Nightly refresh of the network information of every object in scope: the keys of an object that never contributed,
// matched or was read are computed here. A run handles up to REFRESH_MAX_ENTITIES objects and the next one goes on
// after them, starting over once the scope is covered, so that no object waits for ever on a large platform.
export const runPulseRefresh = async (context: AuthContext, force = false) => {
  const { values, platform, state, access } = await loadPulseContext(context);
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
  try {
    await fullEntitiesList<BasicStorePulseEntity>(context, PULSE_MANAGER_USER, values.scopes, {
      noFiltersChecking: true,
      callback: async (entities) => {
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
      },
    });
  } catch (error) {
    await handlePulseReadError(values, error);
    throw error;
  }
  const covered = !remaining;
  await redisSetPulseState({ last_refresh_at: new Date().toISOString(), refresh_offset: covered ? undefined : String(offset + handled) });
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

/**
 * The preview: zero outbound. The digest (the most prevalent published keys of the community, with their prevalence
 * and trend) is downloaded, the keys of the platform's own objects are computed locally and matched, and the coarse
 * signal is written on the matching objects without stream events. No contribution, lookup, trending or benchmark
 * request ever leaves the platform here; nothing leaves, so every object in scope is matched, whatever its markings.
 */
export const runPulsePreview = async (context: AuthContext, force = false) => {
  const { values, platform, state, access } = await loadPulseContext(context);
  if (access !== PulseAccess.Preview || !platform) {
    return 0;
  }
  if (!force && state.preview_refresh_at && Date.now() - Date.parse(state.preview_refresh_at) < REFRESH_INTERVAL_MS) {
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
  // A pass handles up to PREVIEW_MAX_ENTITIES objects; the next one goes on after them and starts over once the
  // scope is covered, so that every object in scope is matched on a large platform.
  const offset = Math.max(0, Number(state.preview_offset ?? 0) || 0);
  let scanned = 0;
  let handled = 0;
  let matched = 0;
  // Set once an object past the cap was seen, as in the nightly refresh.
  let remaining = false;
  await fullEntitiesList<BasicStorePulseEntity>(context, PULSE_MANAGER_USER, values.scopes, {
    noFiltersChecking: true,
    callback: async (entities) => {
      const start = Math.max(0, offset - scanned);
      const room = PREVIEW_MAX_ENTITIES - handled;
      scanned += entities.length;
      remaining = entities.length > start + room;
      const batch = entities.slice(start, start + room);
      handled += batch.length;
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
      return !remaining;
    },
  });
  const covered = !remaining;
  // Every object the preview signal is on, whichever pass wrote it: only preview documents carry a prevalence here.
  const matchedTotal = await elCount(context, PULSE_MANAGER_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    types: values.scopes,
    filters: { mode: FilterMode.And, filters: [{ key: ['pulse_prevalence'], values: [], operator: FilterOperator.NotNil }], filterGroups: [] },
    noFiltersChecking: true,
  });
  await redisSetPulseState({
    preview_refresh_at: updatedAt.toISOString(),
    preview_offset: covered ? undefined : String(offset + handled),
    preview_digest_day: digest.day,
    preview_digest_items: String(digest.items.length),
    preview_matched: String(matchedTotal),
    preview_since: matchedTotal > 0 ? state.preview_since ?? updatedAt.toISOString() : state.preview_since,
  });
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

export const getPulseEntityInformation = async (context: AuthContext, user: AuthUser, id: string) => {
  const { values, platform, access } = await loadPulseContext(context);
  const entity = await storeLoadById<BasicStorePulseEntity>(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const base = { id, access, sector_bucket: values.sectorBucket ?? null, information: null };
  if (!entity || !PULSE_SCOPE_ENTITY_TYPES.includes(entity.entity_type) || !values.scopes.includes(entity.entity_type)) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.OutOfScope };
  }
  if (access === PulseAccess.NotConnected || !platform) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.NotRegistered };
  }
  if (access === PulseAccess.Off) {
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.NotEnabled };
  }
  if (access === PulseAccess.Preview) {
    // The preview signal written by the last digest pass, if the object is among the most prevalent of the community.
    return { ...base, readable: false, unavailable_reason: PulseUnavailableReason.ContributionRequired, information: toPulseInformationOutput(entity) };
  }
  const policy = await buildPulseMarkingPolicy(context, values);
  if (!isPulseContributable(entity, policy, values.scopes)) {
    // Excluded since its last refresh: the statistics it still carries leave the filters, columns and exports now.
    if (hasPulseNetworkData(entity)) {
      await writePulseDocuments(context, [{ entity, doc: PULSE_PREVIEW_CLEARED_DOCUMENT }]);
    }
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
    await handlePulseReadError(values, error);
    const reason = toPulseUnavailableReason(error);
    if (reason === PulseUnavailableReason.ContributionRequired) {
      return { ...base, access: PulseAccess.Preview, readable: false, unavailable_reason: reason };
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
    const entries = await resolveTrendingEntries(context, user, platform, result, entityTypes);
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

// region purge
export const purgePulseContributions = async (context: AuthContext, user: AuthUser) => {
  const { settings, platform, access } = await loadPulseContext(context);
  if (!platform) {
    throw FunctionalError('Register the platform on XTM Hub to purge its Threat Pulse contributions');
  }
  let result: { success: boolean; deleted_records: number };
  // Serialized with the pushes of the contribution: no push runs during the purge, and a cycle started before it
  // records and sends nothing after it (generation). The pending work goes with the purge.
  const lock = await lockResources([PULSE_PUSH_LOCK_KEY]);
  try {
    await redisBumpPulseConfigGeneration();
    try {
      result = await xtmHubPulseClient.purge(platform);
    } catch (error) {
      throw FunctionalError('XTM Hub could not purge the Threat Pulse contributions, retry later', { reason: toPulseUnavailableReason(error) });
    }
    if (!result.success) {
      // The contributions are still on XTM Hub: the local tracking stays, and nothing is audited as purged.
      logApp.warn('[THREAT PULSE] XTM Hub did not purge the Threat Pulse contributions');
      return result;
    }
    await redisClearPulseContributionState(lastUtcDays(STATS_DAYS + 1));
    await redisSetPulseCursor(new Date().toISOString());
  } finally {
    await lock.unlock();
  }
  // XTM Hub no longer holds a contribution of the platform: the full reads wait for the next accepted one.
  await redisSetPulseState({ contribution_accepted: undefined, contribution_lapsed: undefined, last_push_at: undefined, last_refresh_at: undefined, refresh_offset: undefined });
  if (access === PulseAccess.Full) {
    await clearPulseNetworkInformation();
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
