import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  computeEventIncrements,
  deletionDecrements,
  eventsUpTo,
  isFullComputationDue,
  laterStreamEventId,
  mergeBatchIncrements,
  planBackfill,
  planStreamBatch,
  streamBoundaryOf,
} from '../../../../src/manager/sourceIntelligenceManager';
import {
  analystExclusions,
  backfillProgress,
  buildResolverFromSources,
  fingerprintOnKeptSource,
  isKeptOutsideDiscovery,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { recommendationFingerprint } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { buildOverlapShares, createComputeState, processDocument } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-compute';
import {
  type BasicStoreEntitySource,
  RECOMMENDATION_ADD_CONNECTOR,
  RECOMMENDATION_RETIRE,
  SCORECARD_PERIODS,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_PROVENANCE } from '../../../../src/types/stix-2-1-extensions';
import type { AuthContext } from '../../../../src/types/user';
import { buildIntelligenceRoiManifest, SCORECARD_METRICS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-widgets';
import { SCORECARD_NUMERIC_ATTRIBUTES } from '../../../../src/modules/sourceIntelligence/sourceIntelligence';

const settings = { recompute_hour_utc: 2 };

describe('Source intelligence manager scheduling', () => {
  it('should run the first computation at the configured hour, or on request', () => {
    expect(isFullComputationDue({}, settings, Date.UTC(2026, 9, 3, 0, 30))).toBe(false);
    expect(isFullComputationDue({}, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(false);
    expect(isFullComputationDue({}, settings, Date.UTC(2026, 9, 3, 2, 15))).toBe(true);
    expect(isFullComputationDue({ recompute_requested_at: '2026-10-03T10:00:00.000Z' }, settings, Date.UTC(2026, 9, 3, 10, 1))).toBe(true);
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

  it('should run again a computation interrupted while it wrote the live scorecards', () => {
    const state = { last_full_run_day: '2026-10-03', last_full_run_start: '2026-10-03T02:00:00.000Z' };
    expect(isFullComputationDue(state, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(false);
    expect(isFullComputationDue({ ...state, live_rebuild_pending: true }, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(true);
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

  it('should count every pair of sources of an object asserted by more than 50 sources in the overlap', () => {
    const ids = Array.from({ length: 60 }, (_, index) => index);
    const manySources = buildResolverFromSources(ids.map((index) => source(`source-${index}`, 'connector', `connector-${index}`, [`user-${index}`])));
    const doc = {
      internal_id: 'indicator-many-sources',
      entity_type: 'Indicator',
      created_at: iso(DELETED_AT - 2 * DAY),
      updated_at: iso(DELETED_AT - DAY),
      creator_id: ids.map((index) => `user-${index}`),
    };
    const state = createComputeState(DELETED_AT);
    processDocument(state, doc as any, manySources, indicatorSignals, { corroboration_min_other_sources: 1 });
    const pairs = state.pairs.get('LAST_7_DAYS') as Map<string, number>;
    expect(pairs.size).toBe((60 * 59) / 2);
    expect(Array.from(pairs.values()).every((count) => count === 1)).toBe(true);
    const shares = buildOverlapShares(pairs, 'source-0', 1, 100);
    expect(shares).toHaveLength(59);
    expect(shares.every((share) => share.shared_count === 1 && share.share === 1)).toBe(true);
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

  it.each([
    ['set', true, false, 1],
    ['withdrawn', false, true, -1],
  ])('should count a revocation %s in the periods where each source asserted the object', async (_label, value, previous, sign) => {
    const revocation = event('update', { id: 'indicator-1', type: 'Indicator' }, {
      context: {
        patch: [{ op: 'replace', path: '/revoked', value }],
        reverse_patch: [{ op: 'replace', path: '/revoked', value: previous }],
      },
    });
    const { periodIncrements } = await computeEventIncrements({} as AuthContext, [revocation] as any, resolver, {
      enterprise: false,
      huntRunType: null,
      lookups: { documents },
    });
    const counted = { revoked_count: sign };
    expect(byPeriod(periodIncrements as any)).toEqual({
      LAST_7_DAYS: { 'source-feed': counted },
      LAST_30_DAYS: { 'source-feed': counted },
      LAST_90_DAYS: { 'source-connector': counted, 'source-feed': counted },
    });
  });

  it('should not count again a revocation or a sighting the full computation read after the event', async () => {
    const revocation = event('update', { id: 'indicator-1', type: 'Indicator' }, {
      context: {
        patch: [{ op: 'replace', path: '/revoked', value: true }],
        reverse_patch: [{ op: 'replace', path: '/revoked', value: false }],
      },
    });
    const events = [revocation, event('create', sighting)] as any;
    const incrementsWith = async (pageRequestedAt: number, signalsAt: number) => {
      const scanTrace = { started_at: AT - 10 * 60 * 1000, pages: [[pageRequestedAt, 'indicator-9', signalsAt]] as Array<[number, string, number]> };
      const { periodIncrements } = await computeEventIncrements({} as AuthContext, events, resolver, {
        enterprise: false,
        huntRunType: null,
        lookups: { documents },
        scanTrace,
      });
      return byPeriod(periodIncrements as any).LAST_7_DAYS;
    };
    // Page read before both events: the stream counts them
    expect(await incrementsWith(AT - 60 * 1000, AT - 30 * 1000)).toEqual({
      'source-feed': { revoked_count: 1, sightings_count: 1, security_platform_sightings_count: 1 },
    });
    // Object read before the revocation, signals read after the sighting: only the revocation is counted
    expect(await incrementsWith(AT - 60 * 1000, AT + 30 * 1000)).toEqual({ 'source-feed': { revoked_count: 1 } });
    // Page read after both events: the scan already counted them
    expect(await incrementsWith(AT + 30 * 1000, AT + 60 * 1000)).toBeUndefined();
  });

  it('should not count again the creation of an object the full computation scanned', async () => {
    const creation = (createdAt: number) => event('create', { id: 'indicator-2', type: 'Indicator', created_at: iso(createdAt) }, { origin: { user_id: 'user-feed' } });
    const creditedSources = async (createdAt: number, scanTrace = { started_at: AT, pages: [] as Array<[number, string, number]>, truncated: false }) => {
      const { increments } = await computeEventIncrements({} as AuthContext, [creation(createdAt)] as any, resolver, {
        enterprise: false,
        huntRunType: null,
        lookups: { documents },
        scanTrace,
        now: AT + 2000,
      });
      return Array.from(increments.keys());
    };
    // Created before the scan date: the scan counted it, even when its event comes after the stream position
    expect(await creditedSources(AT - 1000)).toEqual([]);
    // Created after the scan date: only the stream counts it
    expect(await creditedSources(AT + 1000)).toEqual(['source-feed']);
    // A truncated scan never read the objects sorted after its last page: the stream counts them
    expect(await creditedSources(AT - 1000, { started_at: AT, pages: [[AT, 'indicator-1', AT]], truncated: true })).toEqual(['source-feed']);
    expect(await creditedSources(AT - 1000, { started_at: AT, pages: [[AT, 'indicator-3', AT]], truncated: true })).toEqual([]);
  });

  it('should count a created object only in the periods whose window still holds it', async () => {
    const creation = event('create', { id: 'indicator-2', type: 'Indicator', created_at: iso(AT - 10 * DAY) }, { origin: { user_id: 'user-feed' } });
    const appliedAt = async (now: number) => {
      const { increments, periodIncrements } = await computeEventIncrements({} as AuthContext, [creation] as any, resolver, {
        enterprise: false,
        huntRunType: null,
        lookups: { documents },
        now,
      });
      expect(increments.get('source-feed')).toEqual({ source_last_asserted_at: AT });
      return byPeriod(periodIncrements as any);
    };
    const volume = { volume_total: 1, new_objects: 1, volume_entities: 1, volume_indicators: 1 };
    // Applied late, after a pause of the stream: out of the last 7 days and of the last day
    expect(await appliedAt(AT)).toEqual({ LAST_30_DAYS: { 'source-feed': volume }, LAST_90_DAYS: { 'source-feed': volume } });
    // Applied on the day it was created: every period, its last day included
    const fresh = { 'source-feed': { ...volume, volume_last_day: 1 } };
    expect(await appliedAt(AT - 10 * DAY + HOUR)).toEqual({ LAST_7_DAYS: fresh, LAST_30_DAYS: fresh, LAST_90_DAYS: fresh });
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

  it('should replay an interrupted batch with its own events only', () => {
    const events = [{ id: '1759500000000-0' }, { id: '1759500000000-7' }, { id: '1759500000001-0' }, { id: '1759500000002-3' }];
    expect(eventsUpTo(events, '1759500000001-0').map(({ id }) => id)).toEqual(['1759500000000-0', '1759500000000-7', '1759500000001-0']);
    expect(eventsUpTo(events, '1759499999999-0')).toEqual([]);
  });

  it('should cap the batches at a pending end without jumping past the events before it', () => {
    const events = [{ id: '1759500000000-0' }, { id: '1759500000001-0' }, { id: '1759500000002-3' }];
    // No pending end: the fetched batch as is
    expect(planStreamBatch(events, '1759500000002-3', undefined)).toEqual({ events, end: '1759500000002-3', pendingEnd: undefined });
    // A pending end within the fetch (an interrupted batch, a full computation boundary): capped at it, then cleared
    const boundary = streamBoundaryOf(1759500000001);
    expect(planStreamBatch(events, '1759500000002-3', boundary)).toEqual({
      events: [{ id: '1759500000000-0' }, { id: '1759500000001-0' }],
      end: boundary,
      pendingEnd: undefined,
    });
    // A pending end beyond the fetch: the fetched batch is applied under its own end, the pending end is kept
    const farBoundary = streamBoundaryOf(1759500009999);
    expect(planStreamBatch(events, '1759500000002-3', farBoundary)).toEqual({ events, end: '1759500000002-3', pendingEnd: farBoundary });
    // Nothing fetched yet up to the pending end: the cursor stays
    expect(planStreamBatch([], '1759499999999-0', farBoundary)).toEqual({ events: [], end: '1759499999999-0', pendingEnd: farBoundary });
  });

  it('should write each live scorecard once per batch, disabled sources excluded', () => {
    const increments = new Map([['source-a', { volume_total: 2, source_last_asserted_at: 10 }], ['source-off', { volume_total: 1 }]]);
    const periodIncrements = new Map([[SCORECARD_PERIODS[0], new Map([['source-a', { volume_total: -1, sightings_count: 1, source_last_asserted_at: 20 }]])]]);
    const merged = mergeBatchIncrements(increments, periodIncrements, new Set(['source-off']));
    expect([...merged.keys()]).toEqual([...SCORECARD_PERIODS]);
    expect(merged.get(SCORECARD_PERIODS[0])?.get('source-a')).toEqual({ volume_total: 1, sightings_count: 1, source_last_asserted_at: 20 });
    expect(merged.get(SCORECARD_PERIODS[1])?.get('source-a')).toEqual({ volume_total: 2, source_last_asserted_at: 10 });
    expect(merged.get(SCORECARD_PERIODS[1])?.has('source-off')).toBe(false);
  });
});

describe('Source intelligence history backfill', () => {
  const NOW = Date.UTC(2026, 9, 3, 12, 0);

  it('should plan the configured range after the first computation', () => {
    expect(planBackfill({}, { backfill_days: 14 }, NOW)).toEqual({
      backfill_from_day: '2026-09-19', backfill_next_day: '2026-09-19', backfill_until_day: '2026-10-03', backfill_done: false,
    });
    expect(planBackfill({}, { backfill_days: 0 }, NOW)).toEqual({ backfill_done: true, backfill_next_day: null });
    expect(planBackfill({ backfill_done: true }, { backfill_days: 0 }, NOW)).toBeNull();
  });

  it('should stop a backfill in progress when the backfill is disabled', () => {
    const inProgress = { backfill_from_day: '2026-09-19', backfill_until_day: '2026-10-03', backfill_next_day: '2026-09-25', backfill_done: false };
    expect(planBackfill(inProgress, { backfill_days: 0 }, NOW)).toEqual({ backfill_done: true, backfill_next_day: null });
    expect(planBackfill({ ...inProgress, backfill_done: true, backfill_next_day: null }, { backfill_days: 0 }, NOW)).toBeNull();
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

describe('Source intelligence author and analyst discovery', () => {
  const departed = {
    internal_id: 'source-author-1',
    source_kind: 'author',
    ref_id: 'identity-1',
    name: 'Former top author',
    enabled: true,
    tags: [],
  } as unknown as BasicStoreEntitySource;

  it('should stop scoring an author or analyst that left the top contributors without being curated', () => {
    expect(isKeptOutsideDiscovery(departed, new Set())).toBe(false);
    expect(isKeptOutsideDiscovery({ ...departed, source_kind: 'manual', quarantined: false, quarantine_draft_id: null } as BasicStoreEntitySource, new Set())).toBe(false);
  });

  it('should keep scoring a departed source someone curated', () => {
    expect(isKeptOutsideDiscovery({ ...departed, source_cost: { amount: 100, currency: 'EUR', period: 'month' } }, new Set())).toBe(true);
    expect(isKeptOutsideDiscovery({ ...departed, description: 'Reviewed every quarter' }, new Set())).toBe(true);
    expect(isKeptOutsideDiscovery({ ...departed, tags: ['paid'] }, new Set())).toBe(true);
    expect(isKeptOutsideDiscovery({ ...departed, owner_id: 'user-1' }, new Set())).toBe(true);
    expect(isKeptOutsideDiscovery({ ...departed, enabled: false }, new Set())).toBe(true);
    expect(isKeptOutsideDiscovery({ ...departed, quarantined: true }, new Set())).toBe(true);
    expect(isKeptOutsideDiscovery({ ...departed, quarantine_draft_id: 'draft-1' }, new Set())).toBe(true);
  });

  it('should keep a departed source while a change applied to it can still be reverted', () => {
    expect(isKeptOutsideDiscovery(departed, new Set(['source-author-1']))).toBe(true);
    expect(isKeptOutsideDiscovery(departed, new Set(['another-source']))).toBe(false);
  });

  it('should leave every account that is not an analyst out of the analyst discovery', () => {
    const users = new Map([
      ['user-analyst', { user_service_account: false }],
      ['user-service', { user_service_account: true }],
      ['user-connector', {}],
    ]);
    const excluded = analystExclusions(new Set(['user-connector']), users);
    expect(excluded).toEqual(expect.arrayContaining(['user-connector', 'user-service', SYSTEM_USER.id]));
    expect(excluded).not.toContain('user-analyst');
  });

  it('should give the recommendations of a merged analyst source the fingerprint of the kept one', () => {
    expect(fingerprintOnKeptSource(recommendationFingerprint(RECOMMENDATION_RETIRE, 'source-2'), 'source-2', 'source-1'))
      .toEqual(recommendationFingerprint(RECOMMENDATION_RETIRE, 'source-1'));
    const gap = recommendationFingerprint(RECOMMENDATION_ADD_CONNECTOR, 'pir-1', 'criterion-source-2', 'connector');
    expect(fingerprintOnKeptSource(gap, 'source-2', 'source-1')).toEqual(gap);
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
