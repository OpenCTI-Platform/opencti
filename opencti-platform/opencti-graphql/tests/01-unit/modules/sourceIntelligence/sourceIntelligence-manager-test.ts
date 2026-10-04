import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  computeEventIncrements,
  deletionDecrements,
  isFullComputationDue,
  laterStreamEventId,
  planBackfill,
  streamBoundaryOf,
} from '../../../../src/manager/sourceIntelligenceManager';
import { backfillProgress, buildResolverFromSources } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-domain';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { createComputeState, processDocument } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-compute';
import { type BasicStoreEntitySource, SCORECARD_PERIODS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_PROVENANCE } from '../../../../src/types/stix-2-1-extensions';
import type { AuthContext } from '../../../../src/types/user';
import { buildIntelligenceRoiManifest, SCORECARD_METRICS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-widgets';
import { SCORECARD_NUMERIC_ATTRIBUTES } from '../../../../src/modules/sourceIntelligence/sourceIntelligence';

const settings = { recompute_hour_utc: 2 };

describe('Source intelligence manager scheduling', () => {
  it('should compute immediately when no full computation ever ran', () => {
    expect(isFullComputationDue({}, settings, Date.UTC(2026, 9, 3, 0, 30))).toBe(true);
  });

  it('should compute once a day after the configured hour', () => {
    const state = { last_full_run_day: '2026-10-02', last_full_run_start: '2026-10-02T02:00:00.000Z' };
    expect(isFullComputationDue(state, settings, Date.UTC(2026, 9, 3, 1, 59))).toBe(false);
    expect(isFullComputationDue(state, settings, Date.UTC(2026, 9, 3, 2, 0))).toBe(true);
    expect(isFullComputationDue({ ...state, last_full_run_day: '2026-10-03' }, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(false);
  });

  it('should honor a recomputation request made after the last run started', () => {
    const state = {
      last_full_run_day: '2026-10-03',
      last_full_run_start: '2026-10-03T02:00:00.000Z',
      recompute_requested_at: '2026-10-03T09:00:00.000Z',
    };
    expect(isFullComputationDue(state, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(true);
    expect(isFullComputationDue({ ...state, last_full_run_start: '2026-10-03T09:01:00.000Z' }, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(false);
  });
});

describe('Source intelligence live deletion accounting', () => {
  const HOUR = 3600 * 1000;
  const DAY = 24 * HOUR;
  const DELETED_AT = Date.UTC(2026, 9, 3, 12, 0);
  const iso = (time: number) => new Date(time).toISOString();
  const source = (internal_id: string, source_kind: string, ref_id: string, users: string[]) => ({
    internal_id, source_kind, ref_id, source_user_ids: users, enabled: true,
  }) as unknown as BasicStoreEntitySource;
  const resolver = buildResolverFromSources([
    source('source-connector', 'connector', 'connector-1', ['user-connector']),
    source('source-feed', 'ingestion_feed', 'feed-1', ['user-feed']),
    source('source-analyst', 'manual', 'user-analyst', ['user-analyst']),
  ]);
  const indicatorSignals = {
    isEntity: true,
    isRelationship: false,
    isIndicator: true,
    isObservable: false,
    negativeRevocation: false,
    negativelySighted: false,
    falsePositive: false,
    negative: false,
    decayExcluded: false,
    pirMatched: false,
    sightings: 0,
    platformSightings: 0,
    huntTruePositives: 0,
    incidents: 0,
    referenced: false,
    sighted: false,
    expired: false,
    noisy: false,
    pulseKnown: false,
    pulseRare: false,
    createdTime: null,
  };
  const COUNTERS = ['volume_total', 'new_objects', 'volume_last_day', 'volume_entities', 'volume_relationships', 'volume_indicators', 'volume_observables'] as const;

  it('should remove a deleted object from the periods where the source was active only', () => {
    const decrements = (created: number, updated: number) => deletionDecrements(resolver, 'Indicator', {
      internal_id: 'indicator-1',
      created_at: iso(created),
      updated_at: iso(updated),
      creator_id: ['user-connector'],
    }, DELETED_AT);
    const recent = decrements(DELETED_AT - 2 * HOUR, DELETED_AT - 2 * HOUR);
    expect(Array.from(recent.keys())).toEqual(['LAST_7_DAYS', 'LAST_30_DAYS', 'LAST_90_DAYS']);
    expect(recent.get('LAST_7_DAYS')?.get('source-connector')).toEqual({
      volume_total: -1, new_objects: -1, volume_last_day: -1, volume_entities: -1, volume_indicators: -1,
    });
    const older = decrements(DELETED_AT - 10 * DAY, DELETED_AT - 10 * DAY);
    expect(Array.from(older.keys())).toEqual(['LAST_30_DAYS', 'LAST_90_DAYS']);
    expect(older.get('LAST_30_DAYS')?.get('source-connector')).toEqual({ volume_total: -1, new_objects: -1, volume_entities: -1, volume_indicators: -1 });
    // Created long ago and asserted again recently: still in the volume of the short periods, not among their new objects
    const reasserted = decrements(DELETED_AT - 60 * DAY, DELETED_AT - 2 * DAY);
    expect(Array.from(reasserted.keys())).toEqual(['LAST_7_DAYS', 'LAST_30_DAYS', 'LAST_90_DAYS']);
    expect(reasserted.get('LAST_7_DAYS')?.get('source-connector')).toEqual({ volume_total: -1, volume_entities: -1, volume_indicators: -1 });
    expect(reasserted.get('LAST_90_DAYS')?.get('source-connector')?.new_objects).toBe(-1);
    expect(decrements(DELETED_AT - 120 * DAY, DELETED_AT - 100 * DAY).size).toBe(0);
  });

  it('should remove exactly what the full computation counts for the object', () => {
    const doc = {
      internal_id: 'indicator-1',
      entity_type: 'Indicator',
      created_at: iso(DELETED_AT - 20 * DAY),
      updated_at: iso(DELETED_AT - 5 * DAY),
      creator_id: ['user-connector', 'user-feed'],
    };
    const state = createComputeState(DELETED_AT);
    processDocument(state, doc as any, resolver, indicatorSignals, { corroboration_min_other_sources: 1 });
    const decrements = deletionDecrements(resolver, 'Indicator', doc, DELETED_AT);
    SCORECARD_PERIODS.forEach((period) => {
      const counted = state.accumulators.get(period) ?? new Map();
      const removed = decrements.get(period) ?? new Map();
      expect(Array.from(removed.keys()).sort()).toEqual(Array.from(counted.keys()).sort());
      counted.forEach((accumulator, sourceId) => {
        COUNTERS.forEach((counter) => expect(accumulator[counter] + (removed.get(sourceId)?.[counter] ?? 0)).toBe(0));
      });
    });
  });

  const deleteEvent = {
    id: `${DELETED_AT}-0`,
    event: 'delete',
    data: {
      type: 'delete',
      origin: { user_id: 'user-analyst' },
      data: {
        extensions: {
          [STIX_EXT_OCTI]: {
            id: 'indicator-1',
            type: 'Indicator',
            created_at: iso(DELETED_AT - 10 * DAY),
            updated_at: iso(DELETED_AT - 10 * DAY),
            creator_ids: ['user-connector'],
          },
          // Streams carry the provenance dates only: the last assertion keeps the object in the short periods
          [STIX_EXT_OCTI_PROVENANCE]: { last_asserted: iso(DELETED_AT - 3 * HOUR) },
        },
      },
    },
  };

  it('should debit the sources recorded on the trash copy of a deleted object, not the deleting user', async () => {
    const trashCopy = {
      internal_id: 'indicator-1',
      created_at: iso(DELETED_AT - 10 * DAY),
      updated_at: iso(DELETED_AT - 10 * DAY),
      creator_id: ['user-connector'],
      x_opencti_assertions: [
        { source_kind: 'connector', source_id: 'connector-1', first_asserted_at: iso(DELETED_AT - 10 * DAY), last_asserted_at: iso(DELETED_AT - 10 * DAY) },
        // A feed asserting the object later, never one of its creators
        { source_kind: 'feed', source_id: 'feed-1', first_asserted_at: iso(DELETED_AT - 3 * DAY), last_asserted_at: iso(DELETED_AT - 3 * HOUR) },
      ],
    };
    const requested: string[][] = [];
    const loadDeletedDocuments = async (ids: string[]) => {
      requested.push(ids);
      return new Map([['indicator-1', trashCopy]]);
    };
    const { increments, periodIncrements: deletions } = await computeEventIncrements({} as AuthContext, [deleteEvent] as any, resolver, {
      enterprise: false,
      huntRunType: null,
      lookups: { deletedDocuments: loadDeletedDocuments },
    });
    expect(requested).toEqual([['indicator-1']]);
    expect(increments.size).toBe(0);
    expect(Array.from(deletions.get('LAST_7_DAYS')?.keys() ?? []).sort()).toEqual(['source-feed']);
    expect(deletions.get('LAST_7_DAYS')?.get('source-feed')).toEqual({
      volume_total: -1, new_objects: -1, volume_last_day: -1, volume_entities: -1, volume_indicators: -1,
    });
    expect(Array.from(deletions.get('LAST_30_DAYS')?.keys() ?? []).sort()).toEqual(['source-connector', 'source-feed']);
    expect(deletions.get('LAST_30_DAYS')?.get('source-connector')).toEqual({ volume_total: -1, new_objects: -1, volume_entities: -1, volume_indicators: -1 });
  });

  it('should debit the creators and the author of a deleted object without trash copy, not the deleting user', async () => {
    const { increments, periodIncrements: deletions } = await computeEventIncrements({} as AuthContext, [deleteEvent] as any, resolver, {
      enterprise: false,
      huntRunType: null,
      lookups: { deletedDocuments: async () => new Map() },
    });
    expect(increments.size).toBe(0);
    expect(Array.from(deletions.keys())).toEqual(['LAST_7_DAYS', 'LAST_30_DAYS', 'LAST_90_DAYS']);
    SCORECARD_PERIODS.forEach((period) => expect(Array.from(deletions.get(period)?.keys() ?? [])).toEqual(['source-connector']));
    expect(deletions.get('LAST_7_DAYS')?.get('source-connector')).toEqual({ volume_total: -1, volume_last_day: -1, volume_entities: -1, volume_indicators: -1 });
    expect(deletions.get('LAST_30_DAYS')?.get('source-connector')?.new_objects).toBe(-1);
  });
});

describe('Source intelligence live signal accounting', () => {
  const HOUR = 3600 * 1000;
  const DAY = 24 * HOUR;
  const AT = Date.UTC(2026, 9, 3, 12, 0);
  const HUNT_RUN_TYPE = 'Hunt-Run';
  const iso = (time: number) => new Date(time).toISOString();
  const source = (internal_id: string, source_kind: string, ref_id: string, users: string[]) => ({
    internal_id, source_kind, ref_id, source_user_ids: users, enabled: true,
  }) as unknown as BasicStoreEntitySource;
  const resolver = buildResolverFromSources([
    source('source-connector', 'connector', 'connector-1', ['user-connector']),
    source('source-feed', 'ingestion_feed', 'feed-1', ['user-feed']),
  ]);
  // Asserted by the connector 60 days ago only, and by the feed in the last hours
  const indicator = {
    internal_id: 'indicator-1',
    created_at: iso(AT - 60 * DAY),
    updated_at: iso(AT - 3 * HOUR),
    creator_id: ['user-connector'],
    x_opencti_assertions: [
      { source_kind: 'connector', source_id: 'connector-1', first_asserted_at: iso(AT - 60 * DAY), last_asserted_at: iso(AT - 60 * DAY) },
      { source_kind: 'feed', source_id: 'feed-1', first_asserted_at: iso(AT - 3 * DAY), last_asserted_at: iso(AT - 3 * HOUR) },
    ],
  };
  const event = (type: string, extension: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    id: `${AT}-0`,
    event: type,
    data: { type, origin: { user_id: 'user-analyst' }, ...extra, data: { extensions: { [STIX_EXT_OCTI]: extension } } },
  });
  const sighting = { id: 'sighting-1', type: STIX_SIGHTING_RELATIONSHIP, sighting_of_ref: 'indicator-1', where_sighted_types: [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM] };
  const documents = async () => new Map([['indicator-1', indicator]]);
  const byPeriod = (periodIncrements: Map<string, Map<string, Record<string, number>>>) => Object.fromEntries(
    Array.from(periodIncrements.entries()).map(([period, patches]) => [period, Object.fromEntries(patches.entries())]),
  );

  it('should credit a sighting only to the periods where each source asserted the object', async () => {
    const { periodIncrements } = await computeEventIncrements({} as AuthContext, [event('create', sighting)] as any, resolver, {
      enterprise: false,
      huntRunType: null,
      lookups: { documents },
    });
    const sighted = { sightings_count: 1, security_platform_sightings_count: 1 };
    expect(byPeriod(periodIncrements as any)).toEqual({
      LAST_7_DAYS: { 'source-feed': sighted },
      LAST_30_DAYS: { 'source-feed': sighted },
      LAST_90_DAYS: { 'source-connector': sighted, 'source-feed': sighted },
    });
  });

  it('should withdraw the signals of deleted sightings and PIR links from the same periods', async () => {
    const events = [
      event('delete', { ...sighting, negative: true }),
      event('delete', { id: 'in-pir-1', type: RELATION_IN_PIR, source_ref: 'indicator-1' }),
    ];
    const { periodIncrements } = await computeEventIncrements({} as AuthContext, events as any, resolver, {
      enterprise: true,
      huntRunType: null,
      lookups: { documents, deletedDocuments: async () => new Map() },
    });
    const withdrawn = { negative_sightings_count: -1, pir_matched_count: -1 };
    expect(byPeriod(periodIncrements as any)).toEqual({
      LAST_7_DAYS: { 'source-feed': withdrawn },
      LAST_30_DAYS: { 'source-feed': withdrawn },
      LAST_90_DAYS: { 'source-connector': withdrawn, 'source-feed': withdrawn },
    });
  });

  it('should withdraw the detections of a hunt run whose true positive verdict is changed', async () => {
    const verdictChange = event('update', { id: 'run-1', type: HUNT_RUN_TYPE }, {
      context: {
        patch: [{ op: 'replace', path: '/verdict', value: 'false_positive' }],
        reverse_patch: [{ op: 'replace', path: '/verdict', value: 'true_positive' }],
      },
    });
    const { periodIncrements } = await computeEventIncrements({} as AuthContext, [verdictChange] as any, resolver, {
      enterprise: false,
      huntRunType: HUNT_RUN_TYPE,
      lookups: {
        documents,
        huntRunSightings: async () => [{ runId: 'run-1', objectId: 'indicator-1' }, { runId: 'run-2', objectId: 'indicator-1' }],
      },
    });
    expect(periodIncrements.get('LAST_7_DAYS')?.get('source-feed')).toEqual({ hunt_true_positives_count: -1 });
    expect(periodIncrements.get('LAST_90_DAYS')?.get('source-connector')).toEqual({ hunt_true_positives_count: -1 });
  });

  it('should withdraw the detection of a deleted sighting of a confirmed hunt run', async () => {
    const requestedRuns: string[][] = [];
    const { periodIncrements } = await computeEventIncrements({} as AuthContext, [event('delete', sighting)] as any, resolver, {
      enterprise: false,
      huntRunType: HUNT_RUN_TYPE,
      lookups: {
        documents,
        deletedDocuments: async () => new Map([['sighting-1', { internal_id: 'sighting-1', creator_id: [], hunt_run_id: 'run-1' }]]),
        trueHuntRunIds: async (runIds) => {
          requestedRuns.push(runIds);
          return ['run-1'];
        },
      },
    });
    expect(requestedRuns).toEqual([['run-1']]);
    expect(periodIncrements.get('LAST_7_DAYS')?.get('source-feed')).toEqual({
      sightings_count: -1, security_platform_sightings_count: -1, hunt_true_positives_count: -1,
    });
  });
});

describe('Source intelligence stream cursor', () => {
  it('should resume the stream after every event the full computation counted', () => {
    const boundary = streamBoundaryOf(1759500000000);
    expect(boundary).toEqual('1759500000000-18446744073709551615');
    // A cursor before the computation time moves to it, events of the same millisecond included
    expect(laterStreamEventId('1759499999000-3', boundary)).toEqual(boundary);
    expect(laterStreamEventId('1759500000000-42', boundary)).toEqual(boundary);
    expect(laterStreamEventId(null, boundary)).toEqual(boundary);
    // A cursor already past it is kept, so later events are never skipped
    expect(laterStreamEventId('1759500000001-0', boundary)).toEqual('1759500000001-0');
  });
});

describe('Source intelligence history backfill', () => {
  const NOW = Date.UTC(2026, 9, 3, 12, 0);

  it('should plan the configured range after the first computation', () => {
    expect(planBackfill({}, { backfill_days: 14 }, NOW)).toEqual({
      backfill_from_day: '2026-09-19', backfill_next_day: '2026-09-19', backfill_until_day: '2026-10-03', backfill_done: false,
    });
    expect(planBackfill({}, { backfill_days: 0 }, NOW)).toEqual({ backfill_done: true });
    expect(planBackfill({ backfill_done: true }, { backfill_days: 0 }, NOW)).toBeNull();
  });

  it('should compute only the missing older days when the range grows', () => {
    const completed = { backfill_from_day: '2026-09-19', backfill_until_day: '2026-10-03', backfill_next_day: null, backfill_done: true };
    expect(planBackfill(completed, { backfill_days: 14 }, NOW + 24 * 3600 * 1000)).toBeNull();
    expect(planBackfill(completed, { backfill_days: 7 }, NOW)).toBeNull();
    expect(planBackfill(completed, { backfill_days: 90 }, NOW)).toEqual({
      backfill_from_day: '2026-07-05', backfill_next_day: '2026-07-05', backfill_until_day: '2026-09-19', backfill_done: false,
    });
    // A pass in progress is extended to the older days, its remaining days included
    const inProgress = { ...completed, backfill_next_day: '2026-09-25', backfill_done: false };
    expect(planBackfill(inProgress, { backfill_days: 90 }, NOW)).toEqual({
      backfill_from_day: '2026-07-05', backfill_next_day: '2026-07-05', backfill_until_day: '2026-10-03', backfill_done: false,
    });
  });

  it('should report the backfill progress in days', () => {
    const state = { backfill_from_day: '2026-09-19', backfill_until_day: '2026-10-03', backfill_next_day: '2026-09-25', backfill_done: false };
    expect(backfillProgress(state)).toEqual({ done: 6, total: 14 });
    expect(backfillProgress({ ...state, backfill_next_day: null, backfill_done: true })).toEqual({ done: 14, total: 14 });
    expect(backfillProgress({})).toBeNull();
  });
});

describe('Source intelligence dashboard widgets', () => {
  it('should only expose scorecard metrics that are stored on the scorecards', () => {
    const stored = new Set(SCORECARD_NUMERIC_ATTRIBUTES.map((attribute) => attribute.name));
    SCORECARD_METRICS.forEach((metric) => expect(stored.has(metric.key)).toBe(true));
  });

  it('should build the Intelligence ROI dashboard on the sources perspective', () => {
    const manifest = JSON.parse(Buffer.from(buildIntelligenceRoiManifest(), 'base64').toString('utf-8'));
    type ManifestWidget = { id: string; type: string; perspective: string; layout: { i: string }; dataSelection: Array<{ attribute: string; perspective: string }> };
    const widgets = Object.values(manifest.widgets) as ManifestWidget[];
    expect(widgets.length).toBeGreaterThanOrEqual(8);
    const metricKeys = new Set(SCORECARD_METRICS.map((metric) => metric.key));
    widgets.forEach((widget) => {
      expect(widget.perspective).toEqual('sources');
      expect(widget.layout.i).toEqual(widget.id);
      widget.dataSelection.forEach((selection) => {
        expect(selection.perspective).toEqual('sources');
        expect(metricKeys.has(selection.attribute as never)).toBe(true);
      });
    });
    expect(widgets.map((widget) => widget.type)).toEqual(expect.arrayContaining(['number', 'bubble', 'horizontal-bar', 'donut', 'list', 'line']));
    expect(manifest.config.relativeDate).toEqual('months-3');
  });
});
