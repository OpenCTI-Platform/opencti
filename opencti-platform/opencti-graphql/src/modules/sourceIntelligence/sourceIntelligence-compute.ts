import { elRawSearch } from '../../database/engine';
import {
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
} from '../../database/utils';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { DatabaseError } from '../../config/errors';
import { logApp } from '../../config/conf';
import { doYield } from '../../utils/eventloop-utils';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import type { SourceIntelligenceSettings } from './sourceIntelligence-settings';
import {
  type BasicStoreEntitySource,
  ENTITY_TYPE_SOURCE_SCORECARD,
  SCORECARD_PERIOD_DAYS,
  SCORECARD_PERIODS,
  type ScorecardPeriodValue,
  type SourceOverlapShare,
  type StoreSourceScorecard,
} from './sourceIntelligence-types';
import { type ProvenanceDocument, type ResolvedAssertion, resolveDocumentAssertions, type SourceResolver } from './sourceIntelligence-provenance';
import {
  computeCostPerActionable,
  computeFreshnessHours,
  computeImpactScore,
  computeLeadTimeHours,
  computeValueScore,
  isExpired,
  isNegativeRevocation,
  ratio,
  ReservoirSample,
  round,
  scorecardDocumentId,
  toSnapshotDate,
} from './sourceIntelligence-scoring';

const HOUR_MS = 3600 * 1000;
const DAY_MS = 24 * HOUR_MS;
const SCAN_PAGE_SIZE = 2000;

// region accumulators
export interface SourceAccumulator {
  volume_total: number;
  volume_entities: number;
  volume_relationships: number;
  volume_indicators: number;
  volume_observables: number;
  new_objects: number;
  volume_last_day: number;
  unique_count: number;
  corroborated_count: number;
  shared_count: number;
  lead_evaluated: number;
  first_reporter_count: number;
  lead_sample: ReservoirSample;
  evaluated_count: number;
  negative_count: number;
  revoked_count: number;
  negative_sightings_count: number;
  false_positive_count: number;
  decay_excluded_count: number;
  pir_matched_count: number;
  sightings_count: number;
  security_platform_sightings_count: number;
  incidents_count: number;
  noise_evaluated: number;
  unreferenced_count: number;
  unsighted_count: number;
  expired_count: number;
  noise_count: number;
  last_asserted_at: number | null;
  latency_sample: ReservoirSample;
  actionable_count: number;
}

const newAccumulator = (): SourceAccumulator => ({
  volume_total: 0,
  volume_entities: 0,
  volume_relationships: 0,
  volume_indicators: 0,
  volume_observables: 0,
  new_objects: 0,
  volume_last_day: 0,
  unique_count: 0,
  corroborated_count: 0,
  shared_count: 0,
  lead_evaluated: 0,
  first_reporter_count: 0,
  lead_sample: new ReservoirSample(),
  evaluated_count: 0,
  negative_count: 0,
  revoked_count: 0,
  negative_sightings_count: 0,
  false_positive_count: 0,
  decay_excluded_count: 0,
  pir_matched_count: 0,
  sightings_count: 0,
  security_platform_sightings_count: 0,
  incidents_count: 0,
  noise_evaluated: 0,
  unreferenced_count: 0,
  unsighted_count: 0,
  expired_count: 0,
  noise_count: 0,
  last_asserted_at: null,
  latency_sample: new ReservoirSample(),
  actionable_count: 0,
});

export interface ComputeState {
  asOf: number;
  accumulators: Map<ScorecardPeriodValue, Map<string, SourceAccumulator>>;
  pairs: Map<ScorecardPeriodValue, Map<string, number>>;
  scanned: number;
  truncated: boolean;
  // Each page read by the scan: when it was requested, the last internal id it returned, when its signal lookups completed
  scanPages: Array<ScanTracePage>;
}

export const createComputeState = (asOf: number): ComputeState => ({
  asOf,
  accumulators: new Map(SCORECARD_PERIODS.map((period) => [period, new Map()])),
  pairs: new Map(SCORECARD_PERIODS.map((period) => [period, new Map()])),
  scanned: 0,
  truncated: false,
  scanPages: [],
});

// Request time of a page, its last internal id and the time the lookups of its signals completed (absent in older traces)
export type ScanTracePage = [number, string, number?];

/**
 * Pages of the last full computation, started at `started_at`, kept to know which deleted objects and which signals
 * given while it scanned it counted.
 */
export interface ScanTrace {
  started_at: number;
  pages: Array<ScanTracePage>;
  // The scan stopped at `max_scan_objects`: the objects sorted after its last page were never read (absent in older traces)
  truncated?: boolean;
}

/**
 * Whether the last full computation counted an object deleted at `time`. The scan reads the knowledge page by page in
 * internal id order, without a snapshot: an object that existed when the computation started and was deleted while it
 * scanned was counted only if its page was read before the deletion. Objects created after the start are counted
 * live, never by the scan.
 */
export const countedByLastScan = (trace: ScanTrace | null | undefined, objectId: string, createdAt: number | null, time: number): boolean => {
  if (!trace || time <= trace.started_at || (createdAt !== null && createdAt > trace.started_at)) {
    return true;
  }
  const page = trace.pages.find(([, lastId]) => objectId <= lastId);
  return page !== undefined && time > page[0];
};

/**
 * Whether the last full computation counted the creation of an object: the scan reads every object created up to its
 * start, the stream adds the later ones. Both read the same creation date, so an object counts once whichever side of
 * the stream position its event fell. A truncated scan read the objects up to its last page only: the stream counts
 * the ones sorted after it.
 */
export const creationCountedByLastScan = (trace: ScanTrace | null | undefined, objectId: string, createdAt: number | null): boolean => {
  if (!trace || createdAt === null || createdAt > trace.started_at) {
    return false;
  }
  return trace.truncated !== true || trace.pages.some(([, lastId]) => objectId <= lastId);
};

/**
 * Whether the last full computation already counted a signal given to an object at `time` while it scanned (a
 * revocation, read with the object, or a sighting or PIR match, read with the signals of its page): the
 * scan read it after the event. The stream applies the signal otherwise, so a change made during the scan counts once.
 */
export const signalSeenByLastScan = (
  trace: ScanTrace | null | undefined,
  objectId: string,
  createdAt: number | null,
  time: number,
  readWith: 'object' | 'signals',
): boolean => {
  if (!trace || time <= trace.started_at || (createdAt !== null && createdAt > trace.started_at)) {
    return false;
  }
  const page = trace.pages.find(([, lastId]) => objectId <= lastId);
  if (page === undefined) {
    return false;
  }
  const [requestedAt, , signalsAt] = page;
  return time < (readWith === 'signals' ? (signalsAt ?? requestedAt) : requestedAt);
};

const accumulatorOf = (state: ComputeState, period: ScorecardPeriodValue, sourceId: string): SourceAccumulator => {
  const periodAccumulators = state.accumulators.get(period) as Map<string, SourceAccumulator>;
  let accumulator = periodAccumulators.get(sourceId);
  if (!accumulator) {
    accumulator = newAccumulator();
    periodAccumulators.set(sourceId, accumulator);
  }
  return accumulator;
};

export const pairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`);
// endregion

// region document signals
export interface ScanDocument extends ProvenanceDocument {
  entity_type: string;
  created?: string;
  revoked?: boolean;
  valid_until?: string | null;
  x_opencti_score?: number | null;
  decay_applied_rule?: { decay_revoke_score?: number | null } | null;
  decay_exclusion_applied_rule?: { decay_exclusion_id?: string } | null;
  'rel_object-label.internal_id'?: string[] | string;
  pir_information?: Array<{ pir_id: string; pir_score: number; last_pir_score_date?: string | null }> | null;
  connections?: Array<{ internal_id: string; role: string }>;
}

export interface PageLookups {
  sightings: Map<string, number>;
  negativeSightings: Map<string, number>;
  platformSightings: Map<string, number>;
  relationshipReferences: Map<string, number>;
  relationshipIncidents: Map<string, number>;
  containerReferences: Map<string, number>;
  containerIncidents: Map<string, number>;
  // Objects of the page, and entities its relationships connect, that a PIR links to (Enterprise Edition)
  pirFlagged: Set<string>;
}

export const emptyPageLookups = (): PageLookups => ({
  sightings: new Map(),
  negativeSightings: new Map(),
  platformSightings: new Map(),
  relationshipReferences: new Map(),
  relationshipIncidents: new Map(),
  containerReferences: new Map(),
  containerIncidents: new Map(),
  pirFlagged: new Set(),
});

export interface RunLookups {
  // Signals written after this time are counted by the streaming increments, never by this computation
  asOf: number;
  // A past day of the history backfill: the fields of an object that only have their current value are read from the
  // objects not updated since that day
  historical: boolean;
  falsePositiveLabelIds: Set<string>;
  // PIR relevance is an Enterprise Edition signal, read page by page with the other signals
  pirRelevance: boolean;
}

const asArray = <T>(value: T[] | T | null | undefined): T[] => {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
};

export interface DocumentSignals {
  isEntity: boolean;
  isRelationship: boolean;
  isIndicator: boolean;
  isObservable: boolean;
  negativeRevocation: boolean;
  negativelySighted: boolean;
  falsePositive: boolean;
  negative: boolean;
  decayExcluded: boolean;
  pirMatched: boolean;
  sightings: number;
  platformSightings: number;
  incidents: number;
  referenced: boolean;
  sighted: boolean;
  expired: boolean;
  noisy: boolean;
  createdTime: number | null;
}

/**
 * Whether the revocation, labels and decay exclusion of a document, which only have their current value, are the ones
 * it had at `now`. Every change to them updates the object: one not updated since a past day of the history backfill
 * has them as they were that day, one updated since may carry them from a later day. The live computation reads them
 * as they are, the stream applying the changes made after its pages were read.
 */
export const currentStateKnownAt = (doc: ScanDocument, run: Pick<RunLookups, 'historical'>, now: number): boolean => {
  if (!run.historical) {
    return true;
  }
  const updated = new Date(doc.updated_at ?? doc.created_at ?? Number.NaN).getTime();
  return Number.isFinite(updated) && updated <= now;
};

/**
 * Whether a PIR score of a document is the one it had at `now`. The PIR scores change without updating the object:
 * a past day of the history backfill only counts a score that last changed before it.
 */
export const pirScoreKnownAt = (info: { last_pir_score_date?: string | null }, run: Pick<RunLookups, 'historical'>, now: number): boolean => {
  if (!run.historical) {
    return true;
  }
  const scored = new Date(info.last_pir_score_date ?? Number.NaN).getTime();
  return Number.isFinite(scored) && scored <= now;
};

export const computeDocumentSignals = (doc: ScanDocument, page: PageLookups, run: RunLookups, now: number): DocumentSignals => {
  const id = doc.internal_id;
  const isRelationship = isStixCoreRelationship(doc.entity_type) || doc.entity_type === STIX_SIGHTING_RELATIONSHIP;
  const isEntity = !isRelationship;
  const isIndicator = doc.entity_type === ENTITY_TYPE_INDICATOR;
  const isObservable = isStixCyberObservable(doc.entity_type);
  // A revocation, false positive label or decay exclusion that cannot be dated never reaches back into a past day:
  // only the signals dated before it (sightings, relationships, containers) count for such an object
  const known = currentStateKnownAt(doc, run, now);
  const negativeRevocation = known && isNegativeRevocation(doc);
  const negativelySighted = (page.negativeSightings.get(id) ?? 0) > 0;
  const labels = known ? asArray(doc['rel_object-label.internal_id']) : [];
  const falsePositive = labels.some((labelId) => run.falsePositiveLabelIds.has(labelId));
  const decayExcluded = known && !!doc.decay_exclusion_applied_rule?.decay_exclusion_id;
  const negative = negativeRevocation || negativelySighted || falsePositive || decayExcluded;
  let pirMatched = false;
  if (run.pirRelevance) {
    if (isEntity) {
      pirMatched = (doc.pir_information ?? []).some((info) => info.pir_score > 0 && pirScoreKnownAt(info, run, now)) || page.pirFlagged.has(id);
    } else {
      pirMatched = (doc.connections ?? []).some((connection) => page.pirFlagged.has(connection.internal_id));
    }
  }
  const sightings = page.sightings.get(id) ?? 0;
  const platformSightings = page.platformSightings.get(id) ?? 0;
  const incidents = (page.relationshipIncidents.get(id) ?? 0) + (page.containerIncidents.get(id) ?? 0);
  const referenced = (page.relationshipReferences.get(id) ?? 0) + (page.containerReferences.get(id) ?? 0) > 0;
  const sighted = sightings > 0 || platformSightings > 0;
  // The end of validity is a date compared with `now`; an expiration by decay revocation is read like the revocation
  const expired = isEntity && isExpired(known ? doc : { ...doc, revoked: false }, now);
  const noisy = isEntity && (expired || (!referenced && !sighted));
  const createdTime = doc.created ? new Date(doc.created).getTime() : null;
  return {
    isEntity,
    isRelationship,
    isIndicator,
    isObservable,
    negativeRevocation,
    negativelySighted,
    falsePositive,
    negative,
    decayExcluded,
    pirMatched,
    sightings,
    platformSightings,
    incidents,
    referenced,
    sighted,
    expired,
    noisy,
    createdTime: createdTime !== null && Number.isFinite(createdTime) ? createdTime : null,
  };
};
// endregion

export interface AssertionActivity extends ResolvedAssertion {
  start: number;
  end: number;
}

/**
 * Span of the assertions of one source on one object, bounded by the computation time. Undated assertions fall back
 * to the creation and last update of the object. Only the first and last assertions are stored: when the source
 * asserted the object again after `asOf` (a past day of the history backfill), the last assertion known at `asOf`
 * is the first one, so a past snapshot never counts an assertion it could not have seen.
 */
export const toAssertionActivity = (assertion: ResolvedAssertion, docCreated: number, docUpdated: number, asOf: number): AssertionActivity => {
  const start = assertion.firstAt ?? docCreated;
  const last = assertion.lastAt ?? docUpdated;
  return { ...assertion, start, end: Math.min(last <= asOf ? last : start, asOf) };
};

/**
 * How an object counts for one source in the period starting at `windowStart`: in its volume when the source asserted
 * it during the period, among its new objects when the first assertion falls in the period, in its last-day volume.
 */
export const periodCounting = (activity: AssertionActivity, windowStart: number, asOf: number) => ({
  inVolume: activity.end >= windowStart,
  isNew: activity.firstAt !== null && activity.firstAt >= windowStart,
  lastDay: activity.end >= asOf - DAY_MS,
});

/**
 * Account one stored document in every period it belongs to, for every source having asserted it.
 */
export const processDocument = (
  state: ComputeState,
  doc: ScanDocument,
  resolver: SourceResolver,
  signals: DocumentSignals,
  settings: Pick<SourceIntelligenceSettings, 'corroboration_min_other_sources'>,
) => {
  const { asOf } = state;
  const docCreated = doc.created_at ? new Date(doc.created_at).getTime() : asOf;
  const docUpdated = doc.updated_at ? new Date(doc.updated_at).getTime() : docCreated;
  const assertions = resolveDocumentAssertions(doc, resolver)
    .map((assertion) => toAssertionActivity(assertion, docCreated, docUpdated, asOf))
    .filter((assertion) => assertion.start <= asOf);
  if (assertions.length === 0) {
    return;
  }
  for (let p = 0; p < SCORECARD_PERIODS.length; p += 1) {
    const period = SCORECARD_PERIODS[p];
    const windowStart = asOf - SCORECARD_PERIOD_DAYS[period] * DAY_MS;
    // Peers, uniqueness and lead time of a period only consider the sources asserting the object during that period
    const inWindow = assertions.filter((assertion) => periodCounting(assertion, windowStart, asOf).inVolume);
    const distinctSources = inWindow.length;
    const otherSources = distinctSources - 1;
    for (let i = 0; i < inWindow.length; i += 1) {
      const assertion = inWindow[i];
      const counting = periodCounting(assertion, windowStart, asOf);
      const acc = accumulatorOf(state, period, assertion.sourceId);
      acc.volume_total += 1;
      if (signals.isRelationship) acc.volume_relationships += 1;
      if (signals.isEntity) acc.volume_entities += 1;
      if (signals.isIndicator) acc.volume_indicators += 1;
      if (signals.isObservable) acc.volume_observables += 1;
      if (counting.isNew) acc.new_objects += 1;
      if (counting.lastDay) acc.volume_last_day += 1;
      // Uniqueness and corroboration
      if (distinctSources === 1) acc.unique_count += 1;
      if (otherSources >= settings.corroboration_min_other_sources) acc.corroborated_count += 1;
      // Lead time over the next source asserting the same object
      if (distinctSources >= 2) {
        acc.shared_count += 1;
        if (assertion.firstAt !== null) {
          const othersFirst = inWindow
            .filter((other) => other.sourceId !== assertion.sourceId && other.firstAt !== null)
            .map((other) => other.firstAt as number);
          const lead = computeLeadTimeHours(assertion.firstAt, othersFirst);
          if (lead !== null) {
            acc.lead_evaluated += 1;
            acc.lead_sample.add(lead);
            if (lead >= 0) acc.first_reporter_count += 1;
          }
        }
      }
      // Accuracy
      acc.evaluated_count += 1;
      if (signals.negative) acc.negative_count += 1;
      if (signals.negativeRevocation) acc.revoked_count += 1;
      if (signals.negativelySighted) acc.negative_sightings_count += 1;
      if (signals.falsePositive) acc.false_positive_count += 1;
      if (signals.decayExcluded) acc.decay_excluded_count += 1;
      // Relevance
      if (signals.pirMatched) acc.pir_matched_count += 1;
      // Impact
      acc.sightings_count += signals.sightings;
      acc.security_platform_sightings_count += signals.platformSightings;
      acc.incidents_count += signals.incidents;
      // Noise (entities only, relationships are context by nature)
      if (signals.isEntity) {
        acc.noise_evaluated += 1;
        if (!signals.referenced) acc.unreferenced_count += 1;
        if (!signals.sighted) acc.unsighted_count += 1;
        if (signals.expired) acc.expired_count += 1;
        if (signals.noisy) acc.noise_count += 1;
      }
      // Freshness and publication latency
      if (acc.last_asserted_at === null || assertion.end > acc.last_asserted_at) acc.last_asserted_at = assertion.end;
      if (assertion.firstAt !== null && signals.createdTime !== null && assertion.firstAt >= signals.createdTime) {
        acc.latency_sample.add((assertion.firstAt - signals.createdTime) / HOUR_MS);
      }
      // Actionable: accurate and not noise
      if (!signals.noisy && !signals.negative) acc.actionable_count += 1;
    }
    // Overlap matrix: every pair counts. The sources of an object are bounded by its creators and authors, and the
    // lead time above already compares each pair.
    if (inWindow.length >= 2) {
      const periodPairs = state.pairs.get(period) as Map<string, number>;
      for (let a = 0; a < inWindow.length; a += 1) {
        for (let b = a + 1; b < inWindow.length; b += 1) {
          const key = pairKey(inWindow[a].sourceId, inWindow[b].sourceId);
          periodPairs.set(key, (periodPairs.get(key) ?? 0) + 1);
        }
      }
    }
  }
};

// region Elasticsearch lookups
const connectionFilter = (ids: string[], role: 'from' | 'to' | 'any') => [
  { terms: { 'connections.internal_id.keyword': ids } },
  ...(role === 'any' ? [] : [{ wildcard: { 'connections.role.keyword': `*_${role}` } }]),
];

const connectionCountAggregation = (ids: string[], role: 'from' | 'to' | 'any') => ({
  connections: {
    nested: { path: 'connections' },
    aggs: {
      matching: {
        filter: { bool: { filter: connectionFilter(ids, role) } },
        aggs: { ids: { terms: { field: 'connections.internal_id.keyword', size: ids.length } } },
      },
    },
  },
});

const bucketsToMap = (aggregation: any, path: string[]): Map<string, number> => {
  let node = aggregation;
  path.forEach((key) => {
    node = node?.[key];
  });
  const result = new Map<string, number>();
  (node?.buckets ?? []).forEach((bucket: { key: string; doc_count: number }) => result.set(bucket.key, bucket.doc_count));
  return result;
};

const rawSearch = async (context: AuthContext, index: string[], body: Record<string, unknown>, size = 0) => {
  return elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_SCORECARD, { index, size, track_total_hits: false, body })
    .catch((err: unknown) => {
      throw DatabaseError('Source intelligence computation query failed', { cause: err });
    });
};

export const fetchPageLookups = async (context: AuthContext, docs: ScanDocument[], run: RunLookups): Promise<PageLookups> => {
  const lookups = emptyPageLookups();
  const ids = docs.map((doc) => doc.internal_id);
  if (ids.length === 0) {
    return lookups;
  }
  const negativeFilter = { term: { x_opencti_negative: true } };
  const sightingsAggs: Record<string, unknown> = {
    positive: { filter: { bool: { must_not: [negativeFilter] } }, aggs: connectionCountAggregation(ids, 'from') },
    negative: { filter: negativeFilter, aggs: connectionCountAggregation(ids, 'from') },
    platform: {
      filter: {
        bool: {
          must_not: [negativeFilter],
          filter: [{
            nested: {
              path: 'connections',
              query: { bool: { filter: [{ wildcard: { 'connections.role.keyword': '*_to' } }, { term: { 'connections.types.keyword': ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } }] } },
            },
          }],
        },
      },
      aggs: connectionCountAggregation(ids, 'from'),
    },
  };
  // Relationships, containers and PIR links created after the computation time are counted by the streaming increments only
  const createdBeforeRun = { range: { created_at: { lte: new Date(run.asOf).toISOString() } } };
  // The negative flag of a sighting only has its current value: a past day of the history backfill counts the
  // sightings not updated since that day (see currentStateKnownAt), never one whose flag may have changed later
  const sightingStateKnown = run.historical
    ? [{
        bool: {
          should: [
            { range: { updated_at: { lte: new Date(run.asOf).toISOString() } } },
            { bool: { must_not: [{ exists: { field: 'updated_at' } }] } },
          ],
          minimum_should_match: 1,
        },
      }]
    : [];
  // A relationship is PIR relevant through the entities it connects: they are looked up with the objects of the page
  const pirIds = run.pirRelevance
    ? [...new Set([...ids, ...docs.flatMap((doc) => (doc.connections ?? []).map((connection) => connection.internal_id))])]
    : [];
  const pirLookup = pirIds.length > 0
    ? rawSearch(context, [READ_INDEX_INTERNAL_RELATIONSHIPS], {
        query: {
          bool: {
            filter: [
              { term: { 'entity_type.keyword': RELATION_IN_PIR } },
              createdBeforeRun,
              { nested: { path: 'connections', query: { bool: { filter: connectionFilter(pirIds, 'from') } } } },
            ],
          },
        },
        aggs: connectionCountAggregation(pirIds, 'from'),
      })
    : Promise.resolve(null);
  const [sightingsData, relationshipsData, containersData, pirData] = await Promise.all([
    rawSearch(context, [READ_INDEX_STIX_SIGHTING_RELATIONSHIPS], {
      query: { bool: { filter: [createdBeforeRun, ...sightingStateKnown, { nested: { path: 'connections', query: { bool: { filter: connectionFilter(ids, 'from') } } } }] } },
      aggs: sightingsAggs,
    }),
    rawSearch(context, [READ_INDEX_STIX_CORE_RELATIONSHIPS], {
      query: { bool: { filter: [createdBeforeRun, { nested: { path: 'connections', query: { bool: { filter: connectionFilter(ids, 'any') } } } }] } },
      aggs: {
        all: { filter: { match_all: {} }, aggs: connectionCountAggregation(ids, 'any') },
        incidents: {
          filter: { nested: { path: 'connections', query: { term: { 'connections.types.keyword': ENTITY_TYPE_INCIDENT } } } },
          aggs: connectionCountAggregation(ids, 'any'),
        },
      },
    }),
    rawSearch(context, [READ_INDEX_STIX_DOMAIN_OBJECTS], {
      query: {
        bool: {
          filter: [
            createdBeforeRun,
            { term: { 'parent_types.keyword': ENTITY_TYPE_CONTAINER } },
            { terms: { 'rel_object.internal_id.keyword': ids } },
          ],
        },
      },
      aggs: {
        all: { terms: { field: 'rel_object.internal_id.keyword', include: ids, size: ids.length } },
        incidents: {
          filter: { term: { 'entity_type.keyword': ENTITY_TYPE_CONTAINER_CASE_INCIDENT } },
          aggs: { ids: { terms: { field: 'rel_object.internal_id.keyword', include: ids, size: ids.length } } },
        },
      },
    }),
    pirLookup,
  ]);
  const sightingsAggregations = sightingsData.aggregations ?? {};
  lookups.sightings = bucketsToMap(sightingsAggregations, ['positive', 'connections', 'matching', 'ids']);
  lookups.negativeSightings = bucketsToMap(sightingsAggregations, ['negative', 'connections', 'matching', 'ids']);
  lookups.platformSightings = bucketsToMap(sightingsAggregations, ['platform', 'connections', 'matching', 'ids']);
  const relationshipsAggregations = relationshipsData.aggregations ?? {};
  lookups.relationshipReferences = bucketsToMap(relationshipsAggregations, ['all', 'connections', 'matching', 'ids']);
  lookups.relationshipIncidents = bucketsToMap(relationshipsAggregations, ['incidents', 'connections', 'matching', 'ids']);
  const containersAggregations = containersData.aggregations ?? {};
  lookups.containerReferences = bucketsToMap(containersAggregations, ['all']);
  lookups.containerIncidents = bucketsToMap(containersAggregations, ['incidents', 'ids']);
  lookups.pirFlagged = new Set(bucketsToMap(pirData?.aggregations ?? {}, ['connections', 'matching', 'ids']).keys());
  return lookups;
};

export const resolveFalsePositiveLabelIds = async (context: AuthContext, labels: string[]): Promise<Set<string>> => {
  if (labels.length === 0) {
    return new Set();
  }
  const data = await rawSearch(context, [READ_INDEX_STIX_META_OBJECTS], {
    query: { bool: { filter: [{ term: { 'entity_type.keyword': ENTITY_TYPE_LABEL } }, { terms: { 'value.keyword': labels } }] } },
    _source: ['internal_id'],
  }, 1000);
  return new Set((data.hits?.hits ?? []).map((hit: any) => hit._source.internal_id as string));
};

export const prepareRunLookups = async (
  context: AuthContext,
  settings: SourceIntelligenceSettings,
  enterprise: boolean,
  asOf: number,
  historical: boolean,
): Promise<RunLookups> => {
  const falsePositiveLabelIds = await resolveFalsePositiveLabelIds(context, settings.false_positive_labels);
  return { asOf, historical, falsePositiveLabelIds, pirRelevance: enterprise };
};
// endregion

const SCAN_SOURCE_FIELDS = [
  'internal_id',
  'entity_type',
  'created_at',
  'updated_at',
  'created',
  'revoked',
  'valid_until',
  'x_opencti_score',
  'decay_applied_rule.decay_revoke_score',
  'decay_exclusion_applied_rule.decay_exclusion_id',
  'creator_id',
  'rel_created-by.internal_id',
  'rel_object-label.internal_id',
  'pir_information',
  'connections.internal_id',
  'connections.role',
];

export const buildScanQuery = (asOf: number, windowStart: number) => {
  const startIso = new Date(windowStart).toISOString();
  const should: unknown[] = [
    { range: { updated_at: { gte: startIso } } },
    { range: { created_at: { gte: startIso } } },
  ];
  return {
    bool: {
      filter: [{ range: { created_at: { lte: new Date(asOf).toISOString() } } }],
      should,
      minimum_should_match: 1,
    },
  };
};

/**
 * Size of the next scan page: the documents that remain below the scan limit, plus one that is never scored and only
 * tells whether the scan is truncated.
 */
export const scanPageSize = (maxScanObjects: number, scanned: number) => {
  const remaining = Math.max(0, maxScanObjects - scanned);
  return { remaining, size: Math.min(SCAN_PAGE_SIZE, remaining + 1) };
};

/**
 * Bounded scan of the knowledge asserted during the longest period, accounting every document in all periods at once.
 */
export const scanKnowledge = async (
  context: AuthContext,
  state: ComputeState,
  resolver: SourceResolver,
  settings: SourceIntelligenceSettings,
  run: RunLookups,
) => {
  const maxDays = Math.max(...SCORECARD_PERIODS.map((period) => SCORECARD_PERIOD_DAYS[period]));
  const query = buildScanQuery(state.asOf, state.asOf - maxDays * DAY_MS);
  let searchAfter: unknown[] | undefined;
  for (;;) {
    const { remaining, size } = scanPageSize(settings.max_scan_objects, state.scanned);
    const requestedAt = Date.now();
    const data = await rawSearch(context, [
      READ_INDEX_STIX_DOMAIN_OBJECTS,
      READ_INDEX_STIX_CYBER_OBSERVABLES,
      READ_INDEX_STIX_CORE_RELATIONSHIPS,
      READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
    ], {
      query,
      _source: SCAN_SOURCE_FIELDS,
      sort: [{ 'internal_id.keyword': 'asc' }],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    }, size);
    const hits = data.hits?.hits ?? [];
    if (hits.length === 0) {
      break;
    }
    const scoredHits = hits.slice(0, remaining);
    if (scoredHits.length > 0) {
      const docs: ScanDocument[] = scoredHits.map((hit: any) => hit._source as ScanDocument);
      const pageLookups = await fetchPageLookups(context, docs, run);
      // A signal given before its lookups completed counts as read by them: never applied again by the stream
      state.scanPages.push([requestedAt, docs[docs.length - 1].internal_id, Date.now()]);
      for (let i = 0; i < docs.length; i += 1) {
        await doYield();
        // Expiration is evaluated at the computation time: a backfilled day sees the indicators valid on that day
        const signals = computeDocumentSignals(docs[i], pageLookups, run, state.asOf);
        processDocument(state, docs[i], resolver, signals, settings);
      }
      state.scanned += docs.length;
    }
    if (hits.length > scoredHits.length) {
      state.truncated = true;
      logApp.warn('[OPENCTI-MODULE] Source intelligence scan truncated, increase max_scan_objects to cover the whole period', {
        scanned: state.scanned,
        max_scan_objects: settings.max_scan_objects,
      });
      break;
    }
    if (hits.length < size) {
      break;
    }
    searchAfter = hits[hits.length - 1].sort;
  }
};

// region scorecard documents
/**
 * The `top` sources sharing the most objects with a source, and whether they are all the sources it shares objects with.
 */
export const buildOverlapShares = (pairs: Map<string, number>, sourceId: string, volume: number, top: number): { shares: SourceOverlapShare[]; complete: boolean } => {
  if (volume <= 0) {
    return { shares: [], complete: true };
  }
  const shares: SourceOverlapShare[] = [];
  pairs.forEach((count, key) => {
    const [a, b] = key.split('|');
    if (a === sourceId || b === sourceId) {
      shares.push({ source_id: a === sourceId ? b : a, shared_count: count, share: round(Math.min(1, count / volume)) });
    }
  });
  const sorted = shares.sort((x, y) => y.shared_count - x.shared_count || x.source_id.localeCompare(y.source_id));
  return { shares: sorted.slice(0, top), complete: sorted.length <= top };
};

export const buildScorecardDocuments = (
  state: ComputeState,
  sources: BasicStoreEntitySource[],
  settings: SourceIntelligenceSettings,
  options: { enterprise: boolean; live: boolean; snapshot: boolean },
): StoreSourceScorecard[] => {
  const { asOf } = state;
  const snapshotDate = toSnapshotDate(asOf);
  const computedAt = new Date(asOf).toISOString();
  const documents: StoreSourceScorecard[] = [];
  SCORECARD_PERIODS.forEach((period) => {
    const days = SCORECARD_PERIOD_DAYS[period];
    const periodAccumulators = state.accumulators.get(period) as Map<string, SourceAccumulator>;
    const periodPairs = state.pairs.get(period) as Map<string, number>;
    sources.forEach((source) => {
      const acc = periodAccumulators.get(source.internal_id) ?? newAccumulator();
      const accuracy = acc.evaluated_count > 0 ? round(1 - acc.negative_count / acc.evaluated_count) : null;
      const relevance = options.enterprise ? ratio(acc.pir_matched_count, acc.volume_total) : null;
      const noise = ratio(acc.noise_count, acc.noise_evaluated);
      const impactScore = computeImpactScore(acc);
      const overlap = buildOverlapShares(periodPairs, source.internal_id, acc.volume_total, settings.overlap_top);
      const metrics = {
        volume_total: acc.volume_total,
        volume_entities: acc.volume_entities,
        volume_relationships: acc.volume_relationships,
        volume_indicators: acc.volume_indicators,
        volume_observables: acc.volume_observables,
        new_objects: acc.new_objects,
        volume_last_day: acc.volume_last_day,
        unique_count: acc.unique_count,
        unique_contribution: ratio(acc.unique_count, acc.volume_total) ?? 0,
        corroborated_count: acc.corroborated_count,
        corroboration_rate: ratio(acc.corroborated_count, acc.volume_total) ?? 0,
        shared_count: acc.shared_count,
        lead_time_hours: acc.lead_sample.median(),
        first_reporter_share: ratio(acc.first_reporter_count, acc.lead_evaluated),
        evaluated_count: acc.evaluated_count,
        revoked_count: acc.revoked_count,
        negative_sightings_count: acc.negative_sightings_count,
        false_positive_count: acc.false_positive_count,
        decay_excluded_count: acc.decay_excluded_count,
        accuracy,
        pir_matched_count: options.enterprise ? acc.pir_matched_count : null,
        relevance,
        sightings_count: acc.sightings_count,
        security_platform_sightings_count: acc.security_platform_sightings_count,
        incidents_count: acc.incidents_count,
        impact_score: impactScore,
        unreferenced_count: acc.unreferenced_count,
        unsighted_count: acc.unsighted_count,
        expired_count: acc.expired_count,
        noise_count: acc.noise_count,
        noise,
        source_last_asserted_at: acc.last_asserted_at !== null ? new Date(acc.last_asserted_at).toISOString() : null,
        freshness_hours: computeFreshnessHours(acc.last_asserted_at, asOf),
        median_latency_hours: acc.latency_sample.median(),
        actionable_count: acc.actionable_count,
        cost_per_actionable_object: computeCostPerActionable(source.source_cost, days, acc.actionable_count),
        cost_currency: source.source_cost?.currency ?? null,
        overlap: overlap.shares,
        overlap_complete: overlap.complete,
        value_score: 0,
      };
      metrics.value_score = computeValueScore(metrics, settings.value_weights);
      const base = {
        entity_type: ENTITY_TYPE_SOURCE_SCORECARD as typeof ENTITY_TYPE_SOURCE_SCORECARD,
        base_type: 'ENTITY' as const,
        parent_types: getParentTypes(ENTITY_TYPE_SOURCE_SCORECARD),
        source_id: source.internal_id,
        source_kind: source.source_kind,
        source_name: source.name,
        scorecard_period: period,
        period_start: new Date(asOf - days * DAY_MS).toISOString(),
        period_end: computedAt,
        scorecard_date: snapshotDate,
        computed_at: computedAt,
        created_at: computedAt,
        updated_at: computedAt,
        ...metrics,
      };
      const variants = [
        ...(options.snapshot ? [false] : []),
        ...(options.live ? [true] : []),
      ];
      variants.forEach((isLive) => {
        const internalId = scorecardDocumentId(source.internal_id, period, snapshotDate, isLive);
        documents.push({ ...base, id: internalId, internal_id: internalId, standard_id: `source-scorecard--${internalId}`, is_live: isLive });
      });
    });
  });
  return documents;
};
// endregion
