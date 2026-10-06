import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { DatabaseError, UnsupportedError } from '../config/errors';
import { executionContext, SOURCE_INTELLIGENCE_MANAGER_USER, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent, UpdateEvent } from '../types/event';
import { fetchStreamEventsRangeFromEventId, fetchStreamInfo } from '../database/stream/stream-handler';
import { publishCacheResetEvent, redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';
import { getEntitiesListFromCache } from '../database/cache';
import { internalFindByIds } from '../database/middleware-loader';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE, READ_INDEX_DELETED_OBJECTS } from '../database/utils';
import { isEnterpriseEdition } from '../enterprise-edition/ee';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
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
  getSourceIntelligenceSettings,
  getSourceIntelligenceState,
  isSourceIntelligenceRunning,
  listAllSources,
  type SourceIntelligenceState,
  syncSources,
  updateSourceIntelligenceState,
  writeComputedSourceKpis,
  clearDisabledSourcesLiveData,
} from '../modules/sourceIntelligence/sourceIntelligence-domain';
import {
  buildScorecardDocuments,
  createComputeState,
  periodCounting,
  prepareRunLookups,
  scanKnowledge,
  type ScanTrace,
  countedByLastScan,
  creationCountedByLastScan,
  signalSeenByLastScan,
  toAssertionActivity,
} from '../modules/sourceIntelligence/sourceIntelligence-compute';
import { applyLiveIncrements, type LiveIncrement, purgeScorecardSnapshots, writeScorecards } from '../modules/sourceIntelligence/sourceIntelligence-store';
import {
  buildSourceResolver,
  type ProvenanceDocument,
  resolveDocumentAssertions,
  resolveEventSources,
  type SourceResolver,
} from '../modules/sourceIntelligence/sourceIntelligence-provenance';
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

// region streaming increments
// Highest sequence of a stream event id: `<time>-<max>` is the last possible event of that millisecond
const STREAM_ID_MAX_SEQUENCE = '18446744073709551615';

/** Stream position right after every event of the given time and before. */
export const streamBoundaryOf = (time: number) => `${time}-${STREAM_ID_MAX_SEQUENCE}`;

/**
 * Last event of the stream, read before a full computation scans: every event up to it was written before the scan
 * started, so the stream resumes right after it and never skips an event the scan could not see. Stream ids come from
 * the clock of the stream itself: without a position read from it, the computation fails and runs again later.
 */
export const streamHighWaterMark = async (): Promise<string> => {
  const info = await fetchStreamInfo().catch((err: unknown) => {
    throw DatabaseError('Source intelligence could not read the stream position before a full computation', { cause: err });
  });
  if (!info?.lastEventId) {
    throw DatabaseError('Source intelligence could not read the stream position before a full computation');
  }
  return info.lastEventId;
};

const parseStreamEventId = (id: string): [bigint, bigint] => {
  const [time, sequence] = id.split('-');
  return [BigInt(time || '0'), BigInt(sequence || '0')];
};

/** The later of two stream positions; a missing position is before any other. */
export const laterStreamEventId = (current: string | null | undefined, candidate: string): string => {
  if (!current) {
    return candidate;
  }
  const [currentTime, currentSequence] = parseStreamEventId(current);
  const [candidateTime, candidateSequence] = parseStreamEventId(candidate);
  const currentIsLater = currentTime > candidateTime || (currentTime === candidateTime && currentSequence >= candidateSequence);
  return currentIsLater ? current : candidate;
};

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

const knowledgeVolumePatch = (entityType: string, lastDay: boolean): LiveIncrement => ({
  volume_total: 1,
  new_objects: 1,
  ...(lastDay ? { volume_last_day: 1 } : {}),
  ...typeVolumePatch(entityType, 1),
});

type PeriodIncrements = Map<ScorecardPeriodValue, Map<string, LiveIncrement>>;

const mergePeriodIncrements = (target: PeriodIncrements, addition: PeriodIncrements) => {
  addition.forEach((patches, period) => {
    const periodIncrements = target.get(period) ?? new Map<string, LiveIncrement>();
    patches.forEach((patch, sourceId) => addIncrement(periodIncrements, [sourceId], patch));
    target.set(period, periodIncrements);
  });
};

/**
 * Patches of one object for each of its sources, in each period where the full computation counts the object for that
 * source, under the same rules (`toAssertionActivity`, `periodCounting`). Nothing is credited to or removed from a
 * period that does not count the object.
 */
const countedPeriodPatches = (
  resolver: SourceResolver,
  doc: ProvenanceDocument,
  at: number,
  patchOf: (counting: ReturnType<typeof periodCounting>) => LiveIncrement,
): PeriodIncrements => {
  const result: PeriodIncrements = new Map();
  const docCreated = doc.created_at ? new Date(doc.created_at).getTime() : at;
  const docUpdated = doc.updated_at ? new Date(doc.updated_at).getTime() : docCreated;
  resolveDocumentAssertions(doc, resolver)
    .map((assertion) => toAssertionActivity(assertion, docCreated, docUpdated, at))
    .filter((activity) => activity.start <= at)
    .forEach((activity) => {
      SCORECARD_PERIODS.forEach((period) => {
        const counting = periodCounting(activity, at - SCORECARD_PERIOD_DAYS[period] * DAY_MS, at);
        if (!counting.inVolume) return;
        const periodIncrements = result.get(period) ?? new Map<string, LiveIncrement>();
        addIncrement(periodIncrements, [activity.sourceId], patchOf(counting));
        result.set(period, periodIncrements);
      });
    });
  return result;
};

/**
 * Creation of an object credited to its sources in the periods whose window still holds it at `at`, as the full
 * computation counts a first assertion: a stream applied late (after a pause) never counts it in a window it left.
 */
export const creationIncrements = (sourceIds: string[], entityType: string, createdAt: number, at: number): PeriodIncrements => {
  const result: PeriodIncrements = new Map();
  SCORECARD_PERIODS.forEach((period) => {
    if (sourceIds.length === 0 || createdAt < at - SCORECARD_PERIOD_DAYS[period] * DAY_MS) return;
    const patches = new Map<string, LiveIncrement>();
    addIncrement(patches, sourceIds, knowledgeVolumePatch(entityType, createdAt >= at - DAY_MS));
    result.set(period, patches);
  });
  return result;
};

/**
 * Removal of a deleted object from the live scorecards: what the full computation counts for it in the volume.
 */
export const deletionDecrements = (resolver: SourceResolver, entityType: string, doc: ProvenanceDocument, deletedAt: number) => {
  return countedPeriodPatches(resolver, doc, deletedAt, (counting) => ({
    volume_total: -1,
    ...typeVolumePatch(entityType, -1),
    ...(counting.isNew ? { new_objects: -1 } : {}),
    ...(counting.lastDay ? { volume_last_day: -1 } : {}),
  }));
};

/**
 * A signal on an object (sighting, revocation, PIR link) credited to its sources, or removed from
 * them when it is withdrawn, in the periods where the full computation counts the object for each source.
 */
export const signalIncrements = (resolver: SourceResolver, doc: ProvenanceDocument, patch: LiveIncrement, at: number) => {
  return countedPeriodPatches(resolver, doc, at, () => patch);
};

const sightingPatch = (extension: { negative?: boolean; where_sighted_types?: string[] }, sign: number): LiveIncrement => {
  if (extension.negative === true) {
    return { negative_sightings_count: sign };
  }
  const platform = (extension.where_sighted_types ?? []).includes(ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  return { sightings_count: sign, ...(platform ? { security_platform_sightings_count: sign } : {}) };
};

const reversePatchSetsValue = (event: UpdateEvent, path: string, value: unknown) => {
  return (event.context?.reverse_patch ?? []).some((operation: any) => operation.path === path && operation.op !== 'remove' && operation.value === value);
};

type StoredObject = BasicStoreBase & Record<string, any>;

export type StoredDocument = ProvenanceDocument;

const toStoredDocument = (object: StoredObject): StoredDocument => ({
  internal_id: object.internal_id,
  created_at: object.created_at ? new Date(object.created_at).toISOString() : undefined,
  updated_at: object.updated_at ? new Date(object.updated_at).toISOString() : undefined,
  creator_id: object.creator_id,
  'rel_created-by.internal_id': object['created-by'] ? [object['created-by']] : [],
});

export const loadStoredDocuments = async (context: AuthContext, ids: string[], indices?: string[]) => {
  const result = new Map<string, StoredDocument>();
  const uniqueIds = [...new Set(ids)];
  // Every object, in bounded lookups
  for (let start = 0; start < uniqueIds.length; start += MAX_OBJECTS_LOOKUP) {
    const chunk = uniqueIds.slice(start, start + MAX_OBJECTS_LOOKUP);
    const objects = await internalFindByIds(context, SYSTEM_USER, chunk, indices ? { indices } : {}) as unknown as StoredObject[];
    objects.forEach((object) => result.set(object.internal_id, toStoredDocument(object)));
  }
  return result;
};

/**
 * Lookups of the live accounting. Deleted objects are read from the trash, which keeps their creators and author;
 * objects deleted permanently (trash disabled, forced or bulk deletion) are not in it.
 */
export interface EventLookups {
  documents: (ids: string[]) => Promise<Map<string, StoredDocument>>;
  deletedDocuments: (ids: string[]) => Promise<Map<string, StoredDocument>>;
}

const defaultEventLookups = (context: AuthContext): EventLookups => ({
  documents: (ids) => loadStoredDocuments(context, ids),
  deletedDocuments: (ids) => loadStoredDocuments(context, ids, [READ_INDEX_DELETED_OBJECTS]),
});

export const computeEventIncrements = async (
  context: AuthContext,
  events: Array<SseEvent<DataEvent>>,
  resolver: SourceResolver,
  options: {
    enterprise: boolean;
    lookups?: Partial<EventLookups>;
    scanTrace?: ScanTrace | null;
    now?: number;
  },
) => {
  const lookups: EventLookups = { ...defaultEventLookups(context), ...options.lookups };
  const now = options.now ?? Date.now();
  // Freshness of the sources, applied to the live scorecards of every period
  const increments = new Map<string, LiveIncrement>();
  // Created and deleted objects and signals, applied only to the periods that count the object for each source
  const periodIncrements: PeriodIncrements = new Map();
  const deleted: Array<{ entityType: string; time: number; eventDocument: ProvenanceDocument }> = [];
  // A revocation is read by the scan with the object, the other signals with the signals of its page
  const signals: Array<{ objectId: string; patch: LiveIncrement; time: number; readWith?: 'object' }> = [];
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
      const createdAt = extension.created_at ? Date.parse(extension.created_at) : NaN;
      if (isKnowledge && extension.is_inferred !== true && !creationCountedByLastScan(options.scanTrace, extension.id, Number.isNaN(createdAt) ? null : createdAt)) {
        const sourceIds = resolveEventSources(resolver, {
          originUserId: data.origin?.user_id,
          creatorIds: extension.creator_ids,
          createdByRefId: extension.created_by_ref_id,
        });
        addIncrement(increments, sourceIds, { source_last_asserted_at: time });
        mergePeriodIncrements(periodIncrements, creationIncrements(sourceIds, entityType, Number.isNaN(createdAt) ? time : createdAt, now));
      }
      if (entityType === STIX_SIGHTING_RELATIONSHIP && extension.sighting_of_ref) {
        signals.push({ objectId: extension.sighting_of_ref, patch: sightingPatch(extension, 1), time });
      }
      if (options.enterprise && entityType === RELATION_IN_PIR && extension.source_ref) {
        signals.push({ objectId: extension.source_ref, patch: { pir_matched_count: 1 }, time });
      }
    } else if (data.type === EVENT_TYPE_UPDATE) {
      const updateEvent = data as UpdateEvent;
      if (isKnowledge) {
        // A source updating an object refreshes its freshness
        const sourceIds = resolveEventSources(resolver, { originUserId: data.origin?.user_id });
        addIncrement(increments, sourceIds, { source_last_asserted_at: time });
        // A revocation set or withdrawn adds or removes the object from the revoked ones
        const revoked = patchSetsValue(updateEvent, '/revoked', true);
        const wasRevoked = reversePatchSetsValue(updateEvent, '/revoked', true);
        if (revoked !== wasRevoked) {
          signals.push({ objectId: extension.id, patch: { revoked_count: revoked ? 1 : -1 }, time, readWith: 'object' });
        }
      }
    } else if (data.type === EVENT_TYPE_DELETE) {
      if (isKnowledge && extension.is_inferred !== true) {
        // Streams carry no source identifiers: without the trash copy, the sources are the creators and the author,
        // active until the last update
        deleted.push({
          entityType,
          time,
          eventDocument: {
            internal_id: extension.id,
            created_at: extension.created_at,
            updated_at: extension.updated_at,
            creator_id: extension.creator_ids ?? [],
            'rel_created-by.internal_id': extension.created_by_ref_id ? [extension.created_by_ref_id] : [],
          },
        });
      }
      // A deleted sighting or PIR link withdraws the signal it gave to the object
      if (entityType === STIX_SIGHTING_RELATIONSHIP && extension.sighting_of_ref) {
        signals.push({ objectId: extension.sighting_of_ref, patch: sightingPatch(extension, -1), time });
      }
      if (options.enterprise && entityType === RELATION_IN_PIR && extension.source_ref) {
        signals.push({ objectId: extension.source_ref, patch: { pir_matched_count: -1 }, time });
      }
    }
  }
  // The trash keeps the stored creators and author of a deleted object: the same attribution as the full computation.
  // The user deleting the object is never one of its sources.
  const deletedIds = deleted.map(({ eventDocument }) => eventDocument.internal_id);
  const trashed = deletedIds.length > 0 ? await lookups.deletedDocuments(deletedIds) : new Map<string, StoredDocument>();
  deleted.forEach(({ entityType, time, eventDocument }) => {
    // An object deleted while the last full computation scanned is removed only if the scan counted it
    const createdAt = eventDocument.created_at ? new Date(eventDocument.created_at).getTime() : null;
    if (!countedByLastScan(options.scanTrace, eventDocument.internal_id, createdAt, time)) {
      return;
    }
    const document = trashed.get(eventDocument.internal_id) ?? eventDocument;
    mergePeriodIncrements(periodIncrements, deletionDecrements(resolver, entityType, document, time));
  });
  // The object carrying a signal, or its trash copy when it was deleted in the meantime
  const signalObjectIds = [...new Set(signals.map(({ objectId }) => objectId))];
  const documents = signalObjectIds.length > 0 ? await lookups.documents(signalObjectIds) : new Map<string, StoredDocument>();
  const missingIds = signalObjectIds.filter((objectId) => !documents.has(objectId) && !trashed.has(objectId));
  const trashedSignalObjects = missingIds.length > 0 ? await lookups.deletedDocuments(missingIds) : new Map<string, StoredDocument>();
  signals.forEach(({ objectId, patch, time, readWith }) => {
    const document = documents.get(objectId) ?? trashed.get(objectId) ?? trashedSignalObjects.get(objectId);
    if (!document) {
      return;
    }
    // A signal given while the last full computation scanned is already counted if the scan read it after the event
    const createdAt = document.created_at ? new Date(document.created_at).getTime() : null;
    if (signalSeenByLastScan(options.scanTrace, objectId, createdAt, time, readWith ?? 'signals')) {
      return;
    }
    mergePeriodIncrements(periodIncrements, signalIncrements(resolver, document, patch, time));
  });
  return { increments, periodIncrements };
};

/**
 * One update per source and period for a stream batch: the increments of every period and those of a single period
 * are merged, so each live scorecard is written once under the batch marker. Disabled sources are not scored.
 */
export const mergeBatchIncrements = (
  increments: Map<string, LiveIncrement>,
  periodIncrements: PeriodIncrements,
  disabledSourceIds: Set<string>,
): PeriodIncrements => {
  const merged: PeriodIncrements = new Map();
  SCORECARD_PERIODS.forEach((period) => {
    const patches = new Map<string, LiveIncrement>();
    increments.forEach((patch, sourceId) => addIncrement(patches, [sourceId], patch));
    (periodIncrements.get(period) ?? new Map<string, LiveIncrement>()).forEach((patch, sourceId) => addIncrement(patches, [sourceId], patch));
    disabledSourceIds.forEach((sourceId) => patches.delete(sourceId));
    if (patches.size > 0) {
      merged.set(period, patches);
    }
  });
  return merged;
};

export const parseScanTrace = (value: string | null | undefined): ScanTrace | null => {
  if (!value) {
    return null;
  }
  try {
    const trace = JSON.parse(value);
    return typeof trace?.started_at === 'number' && Array.isArray(trace.pages) ? trace as ScanTrace : null;
  } catch {
    return null;
  }
};

/** Events of a replayed batch: the ones up to its recorded end, never the later ones fetched with them. */
export const eventsUpTo = <T extends { id: string }>(events: T[], end: string) => {
  return events.filter((event) => laterStreamEventId(event.id, end) === end);
};

// End of the batch being applied, recorded before its first write and cleared once the cursor passed it; also the
// stream boundary of a full computation while its live scorecards are being written
const SOURCE_INTELLIGENCE_PENDING_BATCH = `${SOURCE_INTELLIGENCE_MANAGER_CONTEXT}_pending_batch`;

/**
 * Events and end of the next stream batch. A pending end caps the batch once the fetch reaches it, so the events up to
 * it are applied under that end alone (the scorecards that already applied it skip them); a pending end the fetch does
 * not reach yet stays pending for the next batches.
 */
export const planStreamBatch = <T extends { id: string }>(events: T[], fetchedEnd: string, pendingEnd: string | undefined) => {
  if (!pendingEnd || laterStreamEventId(fetchedEnd, pendingEnd) !== fetchedEnd) {
    return { events, end: fetchedEnd, pendingEnd };
  }
  return { events: eventsUpTo(events, pendingEnd), end: pendingEnd, pendingEnd: undefined };
};

const processStreamIncrements = async (context: AuthContext) => {
  const storedEventId = await redisGetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT);
  let lastEventId = storedEventId ?? `${Date.now()}-0`;
  if (!storedEventId) {
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT, lastEventId);
    return;
  }
  const intelligenceState = await getSourceIntelligenceState();
  // Live scorecards written without their scan trace would count again the events the scan read
  if (intelligenceState.live_rebuild_pending) {
    return;
  }
  // A batch interrupted after its first writes is replayed alone, under the same marker: its scorecards already
  // written skip it, the others apply it. A pending end the cursor already passed (full computation) is stale.
  const storedPending = await redisGetManagerEventState(SOURCE_INTELLIGENCE_PENDING_BATCH);
  let pendingEnd = storedPending && laterStreamEventId(lastEventId, storedPending) !== lastEventId ? storedPending : undefined;
  const sources = await getEntitiesListFromCache<BasicStoreEntitySource>(context, SYSTEM_USER, ENTITY_TYPE_SOURCE);
  if (sources.length === 0) {
    return;
  }
  const resolver = buildSourceResolver(sources);
  // Every source takes part in the attribution, only the enabled ones are scored
  const disabledSourceIds = new Set(sources.filter((source) => source.enabled === false).map((source) => source.internal_id));
  const enterprise = await isEnterpriseEdition(context);
  const scanTrace = parseScanTrace(intelligenceState.last_scan_trace);
  for (let batch = 0; batch < MAX_STREAM_BATCHES_PER_RUN; batch += 1) {
    const events: Array<SseEvent<DataEvent>> = [];
    const { lastEventId: nextEventId } = await fetchStreamEventsRangeFromEventId<DataEvent>(
      lastEventId,
      (batchEvents) => {
        events.push(...batchEvents);
      },
      { streamBatchSize: STREAM_BATCH_SIZE, withInternal: true },
    );
    const plan = planStreamBatch(events, nextEventId, pendingEnd);
    pendingEnd = plan.pendingEnd;
    if (plan.end === lastEventId) {
      break;
    }
    // The farther of the two ends is kept: a replay of this batch reaches the same end, a pending one stays pending
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_PENDING_BATCH, pendingEnd ?? plan.end);
    if (plan.events.length > 0) {
      const { increments, periodIncrements } = await computeEventIncrements(context, plan.events, resolver, { enterprise, scanTrace });
      await applyLiveIncrements(context, mergeBatchIncrements(increments, periodIncrements, disabledSourceIds), plan.end);
    }
    lastEventId = plan.end;
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT, lastEventId);
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_PENDING_BATCH, pendingEnd ?? '');
  }
};
// endregion

// region full computation and backfill
const computeAndStore = async (
  context: AuthContext,
  settings: SourceIntelligenceSettings,
  sources: BasicStoreEntitySource[],
  asOf: number,
  options: { live: boolean; snapshot: boolean; enterprise: boolean; streamBoundary?: string },
) => {
  // Every source takes part in the attribution, so that disabling a source does not inflate the uniqueness of the others
  const resolver = buildSourceResolver(sources);
  const state = createComputeState(asOf);
  const run = await prepareRunLookups(context, settings, options.enterprise, asOf, !options.live);
  await scanKnowledge(context, state, resolver, settings, run);
  // A source can be disabled, deleted or given a cost during the scan: the scorecards use its current state
  const currentById = new Map((await listAllSources(context)).map((source) => [source.internal_id, source]));
  const tracked = sources
    .map((source) => currentById.get(source.internal_id))
    .filter((source): source is BasicStoreEntitySource => !!source && source.enabled !== false);
  const built = buildScorecardDocuments(state, tracked, settings, {
    enterprise: options.enterprise,
    live: options.live,
    snapshot: options.snapshot,
  });
  if (!options.live) {
    await writeScorecards(context, built);
    return { tracked, state, documents: built };
  }
  // The live scorecards count every event up to the computation time: they carry its stream boundary, pending until
  // the stream cursor passes it, so a replay after an interruption skips the events they already count
  const boundary = options.streamBoundary;
  if (!boundary) {
    throw UnsupportedError('A live computation needs the stream position read before its scan');
  }
  const documents = built.map((doc) => (doc.is_live ? { ...doc, live_stream_event_id: boundary } : doc));
  const cursor = await redisGetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT);
  if (laterStreamEventId(cursor, boundary) === boundary) {
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_PENDING_BATCH, boundary);
  }
  await updateSourceIntelligenceState({ live_rebuild_pending: true });
  await writeScorecards(context, documents);
  return { tracked, state, documents };
};

export const runFullComputation = async (context: AuthContext, settings: SourceIntelligenceSettings, now = Date.now()) => {
  const startIso = new Date(now).toISOString();
  await updateSourceIntelligenceState({ last_full_run_start: startIso });
  try {
    const enterprise = await isEnterpriseEdition(context);
    const sources = await syncSources(context, settings);
    const streamBoundary = await streamHighWaterMark();
    // The scan reads the objects created up to a date taken after the stream position: an object created in between
    // is scanned, and its replayed creation is then recognised by its date and not counted again
    const scanAsOf = Math.max(now, Date.now());
    const { tracked, state, documents } = await computeAndStore(context, settings, sources, scanAsOf, { live: true, snapshot: true, enterprise, streamBoundary });
    const trace: ScanTrace = { started_at: scanAsOf, pages: state.scanPages, truncated: state.truncated };
    await updateSourceIntelligenceState({ last_scan_trace: JSON.stringify(trace), live_rebuild_pending: false });
    // The live scorecards now count everything written before the scan: the stream resumes after its last event then,
    // so the events the scan already counted are never applied again and the later ones are kept
    const cursor = await redisGetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT);
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_MANAGER_CONTEXT, laterStreamEventId(cursor, streamBoundary));
    await redisSetManagerEventState(SOURCE_INTELLIGENCE_PENDING_BATCH, '');
    const computedAt = new Date(now).toISOString();
    const references = new Map(documents
      .filter((doc) => doc.is_live && doc.scorecard_period === REFERENCE_SCORECARD_PERIOD)
      .map((doc) => [doc.source_id, doc]));
    // The scorecards were built from the costs read before the scan: each source is written with its cost of now
    for (let i = 0; i < tracked.length; i += 1) {
      const source = tracked[i];
      const reference = references.get(source.internal_id);
      if (reference) {
        await writeComputedSourceKpis(context, source, reference, {
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
        });
      }
    }
    // The latest KPIs are side-channel writes: the cached sources (telemetry, quarantine routing) are refreshed once
    await publishCacheResetEvent(ENTITY_TYPE_SOURCE);
    // Sources disabled while the scorecards were written lose the live data this run gave them
    const latestSources = await listAllSources(context);
    await clearDisabledSourcesLiveData(context, latestSources.filter((source) => source.enabled === false));
    await purgeScorecardSnapshots(context, settings.snapshot_retention_days, now);
    if (enterprise) {
      // A truncated scan scored the sources on part of the knowledge only: tuning them from it could quarantine or
      // retire a source on incomplete data, so recommendations and autonomy wait for a complete computation
      if (state.truncated) {
        logApp.warn('[OPENCTI-MODULE] Source intelligence recommendations skipped, the scan was truncated', { scanned: state.scanned });
      } else {
        await generateSourceRecommendations(context, tracked, settings);
      }
      await computeCollectionGaps(context, sources, settings);
      if (!state.truncated) {
        const autonomous = await applyAutonomousRecommendations(context, settings);
        if (autonomous > 0) {
          logApp.info('[OPENCTI-MODULE] Source intelligence autonomy applied recommendations', { autonomous });
        }
      }
    }
    await updateSourceIntelligenceState({
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
 * The historical days to compute so that the trend charts cover `backfill_days`. A longer range set later computes the
 * missing older days only, so the snapshots of the days already covered are kept; a pass in progress is extended.
 */
export const planBackfill = (
  state: SourceIntelligenceState,
  settings: Pick<SourceIntelligenceSettings, 'backfill_days'>,
  now: number,
): Partial<SourceIntelligenceState> | null => {
  if (settings.backfill_days <= 0) {
    // Disabling the backfill also stops a pass in progress
    return !state.backfill_done || state.backfill_next_day ? { backfill_done: true, backfill_next_day: null } : null;
  }
  const requestedFrom = toSnapshotDate(now - settings.backfill_days * DAY_MS);
  const coveredFrom = state.backfill_from_day ?? null;
  if (coveredFrom && requestedFrom >= coveredFrom) {
    return null;
  }
  const inProgress = !state.backfill_done && !!state.backfill_next_day;
  return {
    backfill_from_day: requestedFrom,
    backfill_next_day: requestedFrom,
    backfill_until_day: coveredFrom && !inProgress ? coveredFrom : (state.backfill_until_day ?? toSnapshotDate(now)),
    backfill_done: false,
  };
};

/**
 * One historical day per run, from the oldest to the end of the planned range (yesterday at most), so the trend charts
 * have data from the first day. Sightings, relationships and containers count when created by the end of the day;
 * revocations, false positive labels and decay exclusions count for the objects not updated since, which had them then.
 */
const runBackfillStep = async (context: AuthContext, settings: SourceIntelligenceSettings, state: SourceIntelligenceState, now: number) => {
  if (state.backfill_done || !state.backfill_next_day) {
    return false;
  }
  const today = toSnapshotDate(now);
  const until = state.backfill_until_day && state.backfill_until_day < today ? state.backfill_until_day : today;
  if (state.backfill_next_day >= until) {
    await updateSourceIntelligenceState({ backfill_done: true, backfill_next_day: null });
    return false;
  }
  const dayEnd = new Date(`${state.backfill_next_day}T23:59:59.999Z`).getTime();
  const enterprise = await isEnterpriseEdition(context);
  const sources = await listAllSources(context);
  await computeAndStore(context, settings, sources, dayEnd, { live: false, snapshot: true, enterprise });
  const nextDay = toSnapshotDate(dayEnd + 1);
  await updateSourceIntelligenceState({ backfill_next_day: nextDay, backfill_done: nextDay >= until });
  logApp.info('[OPENCTI-MODULE] Source intelligence backfill day computed', { day: state.backfill_next_day });
  return true;
};

export const isFullComputationDue = (state: SourceIntelligenceState, settings: Pick<SourceIntelligenceSettings, 'recompute_hour_utc'>, now: number) => {
  if (state.live_rebuild_pending) {
    return true;
  }
  if (state.recompute_requested_at && (!state.last_full_run_start || state.recompute_requested_at > state.last_full_run_start)) {
    return true;
  }
  const hour = new Date(now).getUTCHours();
  // The first computation scans the whole knowledge: it waits for the configured hour, unless requested
  if (!state.last_full_run_day) {
    return hour === settings.recompute_hour_utc;
  }
  return state.last_full_run_day !== toSnapshotDate(now) && hour >= settings.recompute_hour_utc;
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
  // Planned after the first computation, when the sources are known, and again whenever the range setting grows
  const backfillPlan = planBackfill(state, settings, now);
  const current = backfillPlan ? await updateSourceIntelligenceState(backfillPlan) : state;
  await runBackfillStep(context, settings, current, now);
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
