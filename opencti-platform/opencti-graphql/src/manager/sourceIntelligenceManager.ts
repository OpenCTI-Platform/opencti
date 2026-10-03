import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SOURCE_INTELLIGENCE_MANAGER_USER, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent, UpdateEvent } from '../types/event';
import { fetchStreamEventsRangeFromEventId } from '../database/stream/stream-handler';
import { publishCacheResetEvent, redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';
import { getEntitiesListFromCache } from '../database/cache';
import { internalFindByIds } from '../database/middleware-loader';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../database/utils';
import { isEnterpriseEdition } from '../enterprise-edition/ee';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_PROVENANCE } from '../types/stix-2-1-extensions';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { isStixCyberObservable } from '../schema/stixCyberObservable';
import { RELATION_IN_PIR } from '../schema/internalRelationship';
import type { BasicStoreBase } from '../types/store';
import { ENTITY_TYPE_INDICATOR } from '../modules/indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../modules/securityPlatform/securityPlatform-types';
import {
  type BasicStoreEntitySource,
  ENTITY_TYPE_SOURCE,
  REFERENCE_SCORECARD_PERIOD,
  SCORECARD_PERIOD_DAYS,
  SCORECARD_PERIODS,
  type ScorecardPeriodValue,
  SOURCE_INTELLIGENCE_MANAGER_ID,
} from '../modules/sourceIntelligence/sourceIntelligence-types';
import {
  buildResolverFromSources,
  getSourceIntelligenceSettings,
  getSourceIntelligenceState,
  isSourceIntelligenceRunning,
  type SourceIntelligenceState,
  syncSources,
  updateSourceIntelligenceState,
  updateSourceLatestKpis,
  clearDisabledSourcesLiveData,
} from '../modules/sourceIntelligence/sourceIntelligence-domain';
import {
  buildScorecardDocuments,
  createComputeState,
  findHuntRunSightedObjects,
  periodCounting,
  prepareRunLookups,
  resolveSoftJoinAvailability,
  scanKnowledge,
  toAssertionActivity,
} from '../modules/sourceIntelligence/sourceIntelligence-compute';
import { applyLiveIncrements, type LiveIncrement, purgeScorecardSnapshots, writeScorecards } from '../modules/sourceIntelligence/sourceIntelligence-store';
import { type ProvenanceDocument, resolveDocumentAssertions, resolveEventSources, type SourceResolver } from '../modules/sourceIntelligence/sourceIntelligence-provenance';
import { toSnapshotDate } from '../modules/sourceIntelligence/sourceIntelligence-scoring';
import type { SourceIntelligenceSettings } from '../modules/sourceIntelligence/sourceIntelligence-settings';
import { applyAutonomousRecommendations, generateSourceRecommendations } from '../modules/sourceIntelligence/sourceIntelligence-recommendations';
import { computeCollectionGaps } from '../modules/sourceIntelligence/sourceIntelligence-gaps';
import { enforceQuarantines } from '../modules/sourceIntelligence/sourceIntelligence-quarantine';

const SOURCE_INTELLIGENCE_MANAGER_LABEL = 'Source intelligence manager';
const SOURCE_INTELLIGENCE_MANAGER_CONTEXT = 'source_intelligence_manager';
const SOURCE_INTELLIGENCE_MANAGER_ENABLED = booleanConf('source_intelligence_manager:enabled', true);
const SOURCE_INTELLIGENCE_MANAGER_LOCK_KEY = conf.get('source_intelligence_manager:lock_key') || 'source_intelligence_manager_lock';
const SOURCE_INTELLIGENCE_MANAGER_INTERVAL = conf.get('source_intelligence_manager:interval') || 60000;
const STREAM_BATCH_SIZE = conf.get('source_intelligence_manager:stream_batch_size') || 5000;
const MAX_STREAM_BATCHES_PER_RUN = 10;
const MAX_OBJECTS_LOOKUP = 5000;
const DAY_MS = 24 * 3600 * 1000;
const HUNT_VERDICT_TRUE_POSITIVE = 'true_positive';

// region streaming increments
const addIncrement = (increments: Map<string, LiveIncrement>, sourceIds: string[], patch: LiveIncrement) => {
  sourceIds.forEach((sourceId) => {
    const current = increments.get(sourceId) ?? {};
    const next: LiveIncrement = { ...current };
    Object.entries(patch).forEach(([key, value]) => {
      const typedKey = key as keyof LiveIncrement;
      if (typedKey === 'source_last_asserted_at') {
        next.source_last_asserted_at = Math.max(current.source_last_asserted_at ?? 0, value as number);
      } else {
        next[typedKey] = ((current[typedKey] as number | undefined) ?? 0) + (value as number);
      }
    });
    increments.set(sourceId, next);
  });
};

const patchSetsValue = (event: UpdateEvent, path: string, value: unknown) => {
  return (event.context?.patch ?? []).some((operation: any) => operation.path === path && operation.op !== 'remove' && operation.value === value);
};

// Volume counters of the object type, besides the totals
const typeVolumePatch = (entityType: string, value: number): LiveIncrement => {
  const isRelationship = isStixCoreRelationship(entityType) || entityType === STIX_SIGHTING_RELATIONSHIP;
  return {
    ...(isRelationship ? { volume_relationships: value } : { volume_entities: value }),
    ...(entityType === ENTITY_TYPE_INDICATOR ? { volume_indicators: value } : {}),
    ...(isStixCyberObservable(entityType) ? { volume_observables: value } : {}),
  };
};

const knowledgeVolumePatch = (entityType: string, time: number): LiveIncrement => ({
  volume_total: 1,
  new_objects: 1,
  volume_last_day: 1,
  ...typeVolumePatch(entityType, 1),
  source_last_asserted_at: time,
});

const latestDate = (...dates: Array<string | null | undefined>): string | undefined => {
  const times = dates.map((date) => (date ? new Date(date).getTime() : Number.NaN)).filter((time) => Number.isFinite(time));
  return times.length > 0 ? new Date(Math.max(...times)).toISOString() : undefined;
};

/**
 * Removal of a deleted object from the live scorecards: for each of its sources and each period, what the full
 * computation counts for it, under the same rules (`toAssertionActivity`, `periodCounting`). An object outside a
 * period was never counted in it and is not removed from it.
 */
export const deletionDecrements = (resolver: SourceResolver, entityType: string, doc: ProvenanceDocument, deletedAt: number) => {
  const decrements = new Map<ScorecardPeriodValue, Map<string, LiveIncrement>>();
  const docCreated = doc.created_at ? new Date(doc.created_at).getTime() : deletedAt;
  const docUpdated = doc.updated_at ? new Date(doc.updated_at).getTime() : docCreated;
  resolveDocumentAssertions(doc, resolver)
    .map((assertion) => toAssertionActivity(assertion, docCreated, docUpdated, deletedAt))
    .filter((activity) => activity.start <= deletedAt)
    .forEach((activity) => {
      SCORECARD_PERIODS.forEach((period) => {
        const counting = periodCounting(activity, deletedAt - SCORECARD_PERIOD_DAYS[period] * DAY_MS, deletedAt);
        if (!counting.inVolume) return;
        const periodDecrements = decrements.get(period) ?? new Map<string, LiveIncrement>();
        addIncrement(periodDecrements, [activity.sourceId], {
          volume_total: -1,
          ...typeVolumePatch(entityType, -1),
          ...(counting.isNew ? { new_objects: -1 } : {}),
          ...(counting.lastDay ? { volume_last_day: -1 } : {}),
        });
        decrements.set(period, periodDecrements);
      });
    });
  return decrements;
};

const resolveStoredSources = async (context: AuthContext, resolver: SourceResolver, ids: string[]) => {
  const result = new Map<string, string[]>();
  const uniqueIds = [...new Set(ids)].slice(0, MAX_OBJECTS_LOOKUP);
  if (uniqueIds.length === 0) {
    return result;
  }
  const objects = await internalFindByIds(context, SYSTEM_USER, uniqueIds) as unknown as Array<BasicStoreBase & Record<string, any>>;
  objects.forEach((object) => {
    const assertions = resolveDocumentAssertions({
      internal_id: object.internal_id,
      created_at: object.created_at ? new Date(object.created_at).toISOString() : undefined,
      updated_at: object.updated_at ? new Date(object.updated_at).toISOString() : undefined,
      creator_id: object.creator_id,
      'rel_created-by.internal_id': object['created-by'] ? [object['created-by']] : [],
      x_opencti_assertions: object.x_opencti_assertions,
    }, resolver);
    result.set(object.internal_id, assertions.map((assertion) => assertion.sourceId));
  });
  return result;
};

export const computeEventIncrements = async (
  context: AuthContext,
  events: Array<SseEvent<DataEvent>>,
  resolver: SourceResolver,
  options: { enterprise: boolean; huntRunType: string | null },
) => {
  // Applied to the live scorecards of every period
  const increments = new Map<string, LiveIncrement>();
  // Deleted objects, removed only from the periods whose window contains their creation
  const deletions = new Map<ScorecardPeriodValue, Map<string, LiveIncrement>>();
  const sightings: Array<{ objectId: string; platform: boolean; negative: boolean }> = [];
  const revoked: string[] = [];
  const pirFlagged: string[] = [];
  const huntRuns: string[] = [];
  for (let i = 0; i < events.length; i += 1) {
    const event = events[i];
    const data = event.data as any;
    const stix = data?.data;
    const extension = stix?.extensions?.[STIX_EXT_OCTI];
    if (!extension) continue;
    const time = parseInt(event.id.split('-')[0], 10) || Date.now();
    const entityType: string = extension.type;
    const isKnowledge = isStixCoreObject(entityType) || isStixCoreRelationship(entityType) || entityType === STIX_SIGHTING_RELATIONSHIP;
    if (data.type === EVENT_TYPE_CREATE) {
      if (isKnowledge && extension.is_inferred !== true) {
        const sourceIds = resolveEventSources(resolver, {
          originUserId: data.origin?.user_id,
          creatorIds: extension.creator_ids,
          createdByRefId: extension.created_by_ref_id,
          assertions: extension.x_opencti_assertions ?? null,
        });
        addIncrement(increments, sourceIds, knowledgeVolumePatch(entityType, time));
      }
      if (entityType === STIX_SIGHTING_RELATIONSHIP && extension.sighting_of_ref) {
        sightings.push({
          objectId: extension.sighting_of_ref,
          platform: (extension.where_sighted_types ?? []).includes(ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM),
          negative: extension.negative === true,
        });
      }
      if (options.enterprise && entityType === RELATION_IN_PIR && extension.source_ref) {
        pirFlagged.push(extension.source_ref);
      }
    } else if (data.type === EVENT_TYPE_UPDATE) {
      const updateEvent = data as UpdateEvent;
      if (isKnowledge) {
        // A source re-asserting an object refreshes its freshness
        const sourceIds = resolveEventSources(resolver, { originUserId: data.origin?.user_id });
        addIncrement(increments, sourceIds, { source_last_asserted_at: time });
        if (patchSetsValue(updateEvent, '/revoked', true)) {
          revoked.push(extension.id);
        }
      }
      if (options.huntRunType && entityType === options.huntRunType && patchSetsValue(updateEvent, '/verdict', HUNT_VERDICT_TRUE_POSITIVE)) {
        huntRuns.push(extension.id);
      }
    } else if (data.type === EVENT_TYPE_DELETE && isKnowledge && extension.is_inferred !== true) {
      // Streams carry no source identifiers, only provenance dates: the sources are the creators and the author,
      // active until the last update or assertion. The user deleting the object is not one of its sources.
      const provenance = stix.extensions?.[STIX_EXT_OCTI_PROVENANCE];
      const decrements = deletionDecrements(resolver, entityType, {
        internal_id: extension.id,
        created_at: extension.created_at,
        updated_at: latestDate(extension.updated_at, provenance?.last_asserted),
        creator_id: extension.creator_ids ?? [],
        'rel_created-by.internal_id': extension.created_by_ref_id ? [extension.created_by_ref_id] : [],
      }, time);
      decrements.forEach((periodDecrements, period) => {
        const periodIncrements = deletions.get(period) ?? new Map<string, LiveIncrement>();
        periodDecrements.forEach((patch, sourceId) => addIncrement(periodIncrements, [sourceId], patch));
        deletions.set(period, periodIncrements);
      });
    }
  }
  // Hunt runs (innovation 01) write sightings carrying their run id: each sighted object is a confirmed detection
  const huntSightedObjects = huntRuns.length > 0 ? await findHuntRunSightedObjects(context, huntRuns) : [];
  const sourcesByObject = await resolveStoredSources(context, resolver, [
    ...sightings.map((sighting) => sighting.objectId),
    ...revoked,
    ...pirFlagged,
    ...huntSightedObjects,
  ]);
  sightings.forEach((sighting) => {
    const sourceIds = sourcesByObject.get(sighting.objectId) ?? [];
    if (sighting.negative) {
      addIncrement(increments, sourceIds, { negative_sightings_count: 1 });
    } else {
      addIncrement(increments, sourceIds, { sightings_count: 1, ...(sighting.platform ? { security_platform_sightings_count: 1 } : {}) });
    }
  });
  revoked.forEach((objectId) => addIncrement(increments, sourcesByObject.get(objectId) ?? [], { revoked_count: 1 }));
  pirFlagged.forEach((objectId) => addIncrement(increments, sourcesByObject.get(objectId) ?? [], { pir_matched_count: 1 }));
  huntSightedObjects.forEach((objectId) => addIncrement(increments, sourcesByObject.get(objectId) ?? [], { hunt_true_positives_count: 1 }));
  return { increments, deletions };
};

const processStreamIncrements = async (context: AuthContext) => {
  const storedEventId = await redisGetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT);
  let lastEventId = storedEventId ?? `${Date.now()}-0`;
  if (!storedEventId) {
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT, lastEventId);
    return;
  }
  const sources = await getEntitiesListFromCache<BasicStoreEntitySource>(context, SYSTEM_USER, ENTITY_TYPE_SOURCE);
  if (sources.length === 0) {
    return;
  }
  const resolver = buildResolverFromSources(sources);
  // Every source takes part in the attribution, only the enabled ones are scored
  const disabledSourceIds = new Set(sources.filter((source) => source.enabled === false).map((source) => source.internal_id));
  const enterprise = await isEnterpriseEdition(context);
  const { huntRunType } = resolveSoftJoinAvailability();
  for (let batch = 0; batch < MAX_STREAM_BATCHES_PER_RUN; batch += 1) {
    const events: Array<SseEvent<DataEvent>> = [];
    const { lastEventId: nextEventId } = await fetchStreamEventsRangeFromEventId<DataEvent>(
      lastEventId,
      (batchEvents) => {
        events.push(...batchEvents);
      },
      { streamBatchSize: STREAM_BATCH_SIZE, withInternal: true },
    );
    if (events.length > 0) {
      const { increments, deletions } = await computeEventIncrements(context, events, resolver, { enterprise, huntRunType });
      disabledSourceIds.forEach((sourceId) => increments.delete(sourceId));
      await applyLiveIncrements(context, increments, SCORECARD_PERIODS);
      const deletionsByPeriod = Array.from(deletions.entries());
      for (let i = 0; i < deletionsByPeriod.length; i += 1) {
        const [period, periodIncrements] = deletionsByPeriod[i];
        disabledSourceIds.forEach((sourceId) => periodIncrements.delete(sourceId));
        await applyLiveIncrements(context, periodIncrements, [period]);
      }
    }
    if (nextEventId === lastEventId) {
      break;
    }
    lastEventId = nextEventId;
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT, lastEventId);
  }
};
// endregion

// region full computation and backfill
const computeAndStore = async (
  context: AuthContext,
  settings: SourceIntelligenceSettings,
  sources: BasicStoreEntitySource[],
  asOf: number,
  options: { live: boolean; snapshot: boolean; enterprise: boolean },
) => {
  const tracked = sources.filter((source) => source.enabled !== false);
  // Every source takes part in the attribution, so that disabling a source does not inflate the uniqueness of the others
  const resolver = buildResolverFromSources(sources);
  const state = createComputeState(asOf);
  const run = await prepareRunLookups(context, settings, options.enterprise, asOf);
  await scanKnowledge(context, state, resolver, settings, run);
  const documents = buildScorecardDocuments(state, tracked, settings, {
    enterprise: options.enterprise,
    availability: run.availability,
    live: options.live,
    snapshot: options.snapshot,
  });
  await writeScorecards(context, documents);
  return { tracked, state, documents };
};

export const runFullComputation = async (context: AuthContext, settings: SourceIntelligenceSettings, now = Date.now()) => {
  const startIso = new Date(now).toISOString();
  await updateSourceIntelligenceState({ last_full_run_start: startIso });
  try {
    const enterprise = await isEnterpriseEdition(context);
    const sources = await syncSources(context, settings);
    const { tracked, state, documents } = await computeAndStore(context, settings, sources, now, { live: true, snapshot: true, enterprise });
    const computedAt = new Date(now).toISOString();
    const references = new Map(documents
      .filter((doc) => doc.is_live && doc.scorecard_period === REFERENCE_SCORECARD_PERIOD)
      .map((doc) => [doc.source_id, doc]));
    for (let i = 0; i < tracked.length; i += 1) {
      const source = tracked[i];
      const reference = references.get(source.internal_id);
      if (reference) {
        await updateSourceLatestKpis(context, source, {
          last_computed_at: computedAt,
          latest_value_score: reference.value_score,
          latest_volume: reference.volume_total,
          latest_unique_contribution: reference.unique_contribution,
          latest_corroboration_rate: reference.corroboration_rate,
          latest_lead_time_hours: reference.lead_time_hours,
          latest_accuracy: reference.accuracy,
          latest_relevance: reference.relevance,
          latest_impact_score: reference.impact_score,
          latest_noise: reference.noise,
          latest_freshness_hours: reference.freshness_hours,
          latest_cost_per_actionable: reference.cost_per_actionable_object,
          latest_community_uniqueness: reference.community_uniqueness,
        });
      }
    }
    // The latest KPIs are side-channel writes: the cached sources (telemetry, quarantine routing) are refreshed once
    await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
    await clearDisabledSourcesLiveData(context, sources.filter((source) => source.enabled === false));
    await purgeScorecardSnapshots(context, settings.snapshot_retention_days, now);
    if (enterprise) {
      await generateSourceRecommendations(context, tracked, settings);
      await computeCollectionGaps(context, sources, settings);
      const autonomous = await applyAutonomousRecommendations(context, settings);
      if (autonomous > 0) {
        logApp.info('[OPENCTI-MODULE] Source intelligence autonomy applied recommendations', { autonomous });
      }
    }
    const current = await getSourceIntelligenceState();
    const backfillPatch: Partial<SourceIntelligenceState> = {};
    if (!current.backfill_done && !current.backfill_next_day) {
      backfillPatch.backfill_next_day = settings.backfill_days > 0 ? toSnapshotDate(now - settings.backfill_days * DAY_MS) : null;
      backfillPatch.backfill_done = settings.backfill_days === 0;
    }
    await updateSourceIntelligenceState({
      ...backfillPatch,
      last_full_run_day: toSnapshotDate(now),
      last_full_run_end: new Date().toISOString(),
      last_run_success: true,
      last_run_message: `${tracked.length} sources scored over ${state.scanned} objects`,
      last_scanned_objects: state.scanned,
      last_scan_truncated: state.truncated,
    });
    logApp.info('[OPENCTI-MODULE] Source intelligence full computation done', { sources: tracked.length, scanned: state.scanned, truncated: state.truncated });
  } catch (error: any) {
    await updateSourceIntelligenceState({ last_full_run_end: new Date().toISOString(), last_run_success: false, last_run_message: error?.message ?? String(error) });
    throw error;
  }
};

/**
 * One historical day per run, from the oldest to yesterday, so the trend charts have data from the first day.
 * Quality signals (revocations, sightings, labels) are evaluated with their current state.
 */
const runBackfillStep = async (context: AuthContext, settings: SourceIntelligenceSettings, state: SourceIntelligenceState, now: number) => {
  if (state.backfill_done || !state.backfill_next_day) {
    return false;
  }
  const today = toSnapshotDate(now);
  if (state.backfill_next_day >= today) {
    await updateSourceIntelligenceState({ backfill_done: true, backfill_next_day: null });
    return false;
  }
  const dayEnd = new Date(`${state.backfill_next_day}T23:59:59.999Z`).getTime();
  const enterprise = await isEnterpriseEdition(context);
  const sources = await getEntitiesListFromCache<BasicStoreEntitySource>(context, SYSTEM_USER, ENTITY_TYPE_SOURCE);
  await computeAndStore(context, settings, sources, dayEnd, { live: false, snapshot: true, enterprise });
  const nextDay = toSnapshotDate(dayEnd + 1);
  await updateSourceIntelligenceState({ backfill_next_day: nextDay, backfill_done: nextDay >= today });
  logApp.info('[OPENCTI-MODULE] Source intelligence backfill day computed', { day: state.backfill_next_day });
  return true;
};

export const isFullComputationDue = (state: SourceIntelligenceState, settings: Pick<SourceIntelligenceSettings, 'recompute_hour_utc'>, now: number) => {
  if (!state.last_full_run_day) {
    return true;
  }
  if (state.recompute_requested_at && (!state.last_full_run_start || state.recompute_requested_at > state.last_full_run_start)) {
    return true;
  }
  const today = toSnapshotDate(now);
  return state.last_full_run_day !== today && new Date(now).getUTCHours() >= settings.recompute_hour_utc;
};
// endregion

export const sourceIntelligenceHandler = async () => {
  const context = executionContext(SOURCE_INTELLIGENCE_MANAGER_CONTEXT, SOURCE_INTELLIGENCE_MANAGER_USER);
  if (!(await isSourceIntelligenceRunning(context))) {
    return;
  }
  const settings = await getSourceIntelligenceSettings(context);
  try {
    await processStreamIncrements(context);
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Source intelligence streaming increments error', { cause: error, manager: SOURCE_INTELLIGENCE_MANAGER_ID });
  }
  try {
    await enforceQuarantines(context);
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Source intelligence quarantine enforcement error', { cause: error, manager: SOURCE_INTELLIGENCE_MANAGER_ID });
  }
  const now = Date.now();
  const state = await getSourceIntelligenceState();
  if (isFullComputationDue(state, settings, now)) {
    await runFullComputation(context, settings, now);
    return;
  }
  await runBackfillStep(context, settings, state, now);
};

const SOURCE_INTELLIGENCE_MANAGER_DEFINITION: ManagerDefinition = {
  id: SOURCE_INTELLIGENCE_MANAGER_ID,
  label: SOURCE_INTELLIGENCE_MANAGER_LABEL,
  executionContext: SOURCE_INTELLIGENCE_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: sourceIntelligenceHandler,
    interval: SOURCE_INTELLIGENCE_MANAGER_INTERVAL,
    lockKey: SOURCE_INTELLIGENCE_MANAGER_LOCK_KEY,
  },
  enabledByConfig: SOURCE_INTELLIGENCE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(SOURCE_INTELLIGENCE_MANAGER_DEFINITION);
