import { elRawSearch } from '../../database/engine';
import {
  READ_INDEX_INTERNAL_OBJECTS,
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
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { ABSTRACT_INTERNAL_OBJECT, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import type { SourceIntelligenceSettings } from './sourceIntelligence-settings';
import {
  type BasicStoreEntitySource,
  ENTITY_TYPE_SOURCE_SCORECARD,
  type ProvenanceMode,
  SCORECARD_PERIOD_DAYS,
  SCORECARD_PERIODS,
  type ScorecardPeriodValue,
  type SourceOverlapShare,
  type StoreSourceScorecard,
} from './sourceIntelligence-types';
import {
  PROVENANCE_ATTRIBUTE,
  PROVENANCE_LAST_ASSERTED_AT,
  type ProvenanceDocument,
  type ResolvedAssertion,
  resolveDocumentAssertions,
  type SourceResolver,
} from './sourceIntelligence-provenance';
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
const MAX_PIR_FLAGGED_IDS = 500000;
// Values per terms clause, below the default index.max_terms_count of the search engine
const TERMS_CHUNK_SIZE = 10000;
const MAX_COMBINED_SOURCES_PER_DOCUMENT = 50;

// Soft dependencies on sibling innovations: the joins activate when their attributes exist in the schema
export const PULSE_INFORMATION_ATTRIBUTE = 'pulse_information'; // innovation 04 (Threat Pulse)
export const HUNT_RUN_SIGHTING_ATTRIBUTE = 'x_opencti_hunt_run_id'; // innovation 01 (Hunts)
const HUNT_RUN_ENTITY_TYPES = ['Hunt-Run', 'HuntRun'];
const HUNT_VERDICT_TRUE_POSITIVE = 'true_positive';
const PULSE_RARE_BUCKET = 'rare';

export interface SoftJoinAvailability {
  provenance: ProvenanceMode;
  pulse: boolean;
  huntRunType: string | null;
}

export const resolveSoftJoinAvailability = (): SoftJoinAvailability => {
  const huntRunType = HUNT_RUN_ENTITY_TYPES.find((type) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_INTERNAL_OBJECT)) ?? null;
  const huntAvailable = huntRunType !== null && schemaAttributesDefinition.getAttribute(STIX_SIGHTING_RELATIONSHIP, HUNT_RUN_SIGHTING_ATTRIBUTE) !== undefined;
  return {
    provenance: schemaAttributesDefinition.getAttributeByName(PROVENANCE_ATTRIBUTE) !== undefined ? 'assertions' : 'creators',
    pulse: schemaAttributesDefinition.getAttributeByName(PULSE_INFORMATION_ATTRIBUTE) !== undefined,
    huntRunType: huntAvailable ? huntRunType : null,
  };
};

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
  hunt_true_positives_count: number;
  incidents_count: number;
  noise_evaluated: number;
  unreferenced_count: number;
  unsighted_count: number;
  expired_count: number;
  noise_count: number;
  last_asserted_at: number | null;
  latency_sample: ReservoirSample;
  actionable_count: number;
  community_known_count: number;
  community_rare_count: number;
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
  hunt_true_positives_count: 0,
  incidents_count: 0,
  noise_evaluated: 0,
  unreferenced_count: 0,
  unsighted_count: 0,
  expired_count: 0,
  noise_count: 0,
  last_asserted_at: null,
  latency_sample: new ReservoirSample(),
  actionable_count: 0,
  community_known_count: 0,
  community_rare_count: 0,
});

export interface ComputeState {
  asOf: number;
  accumulators: Map<ScorecardPeriodValue, Map<string, SourceAccumulator>>;
  pairs: Map<ScorecardPeriodValue, Map<string, number>>;
  scanned: number;
  truncated: boolean;
}

export const createComputeState = (asOf: number): ComputeState => ({
  asOf,
  accumulators: new Map(SCORECARD_PERIODS.map((period) => [period, new Map()])),
  pairs: new Map(SCORECARD_PERIODS.map((period) => [period, new Map()])),
  scanned: 0,
  truncated: false,
});

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
  pir_information?: Array<{ pir_id: string; pir_score: number }> | null;
  pulse_information?: { prevalence_bucket?: string } | Array<{ prevalence_bucket?: string }> | null;
  connections?: Array<{ internal_id: string; role: string }>;
}

export interface PageLookups {
  sightings: Map<string, number>;
  negativeSightings: Map<string, number>;
  platformSightings: Map<string, number>;
  huntTruePositives: Map<string, number>;
  relationshipReferences: Map<string, number>;
  relationshipIncidents: Map<string, number>;
  containerReferences: Map<string, number>;
  containerIncidents: Map<string, number>;
}

export const emptyPageLookups = (): PageLookups => ({
  sightings: new Map(),
  negativeSightings: new Map(),
  platformSightings: new Map(),
  huntTruePositives: new Map(),
  relationshipReferences: new Map(),
  relationshipIncidents: new Map(),
  containerReferences: new Map(),
  containerIncidents: new Map(),
});

export interface RunLookups {
  // Signals written after this time are counted by the streaming increments, never by this computation
  asOf: number;
  falsePositiveLabelIds: Set<string>;
  pirFlaggedIds: Set<string> | null; // null outside Enterprise Edition
  huntTrueRunIds: string[];
  availability: SoftJoinAvailability;
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
  huntTruePositives: number;
  incidents: number;
  referenced: boolean;
  sighted: boolean;
  expired: boolean;
  noisy: boolean;
  pulseKnown: boolean;
  pulseRare: boolean;
  createdTime: number | null;
}

export const computeDocumentSignals = (doc: ScanDocument, page: PageLookups, run: RunLookups, now: number): DocumentSignals => {
  const id = doc.internal_id;
  const isRelationship = isStixCoreRelationship(doc.entity_type) || doc.entity_type === STIX_SIGHTING_RELATIONSHIP;
  const isEntity = !isRelationship;
  const isIndicator = doc.entity_type === ENTITY_TYPE_INDICATOR;
  const isObservable = isStixCyberObservable(doc.entity_type);
  const negativeRevocation = isNegativeRevocation(doc);
  const negativelySighted = (page.negativeSightings.get(id) ?? 0) > 0;
  const labels = asArray(doc['rel_object-label.internal_id']);
  const falsePositive = labels.some((labelId) => run.falsePositiveLabelIds.has(labelId));
  const decayExcluded = !!doc.decay_exclusion_applied_rule?.decay_exclusion_id;
  const negative = negativeRevocation || negativelySighted || falsePositive || decayExcluded;
  let pirMatched = false;
  if (run.pirFlaggedIds) {
    if (isEntity) {
      pirMatched = (doc.pir_information ?? []).some((info) => info.pir_score > 0) || run.pirFlaggedIds.has(id);
    } else {
      pirMatched = (doc.connections ?? []).some((connection) => run.pirFlaggedIds?.has(connection.internal_id));
    }
  }
  const sightings = page.sightings.get(id) ?? 0;
  const platformSightings = page.platformSightings.get(id) ?? 0;
  const huntTruePositives = page.huntTruePositives.get(id) ?? 0;
  const incidents = (page.relationshipIncidents.get(id) ?? 0) + (page.containerIncidents.get(id) ?? 0);
  const referenced = (page.relationshipReferences.get(id) ?? 0) + (page.containerReferences.get(id) ?? 0) > 0;
  const sighted = sightings > 0 || platformSightings > 0;
  const expired = isEntity && isExpired(doc, now);
  const noisy = isEntity && (expired || (!referenced && !sighted));
  const pulse = asArray(doc.pulse_information)[0];
  const pulseKnown = run.availability.pulse && isIndicator && !!pulse;
  const pulseRare = pulseKnown && pulse?.prevalence_bucket === PULSE_RARE_BUCKET;
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
    huntTruePositives,
    incidents,
    referenced,
    sighted,
    expired,
    noisy,
    pulseKnown,
    pulseRare,
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
 * to the creation and last update of the object.
 */
export const toAssertionActivity = (assertion: ResolvedAssertion, docCreated: number, docUpdated: number, asOf: number): AssertionActivity => ({
  ...assertion,
  start: assertion.firstAt ?? docCreated,
  end: Math.min(assertion.lastAt ?? docUpdated, asOf),
});

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
      acc.hunt_true_positives_count += signals.huntTruePositives;
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
      // Threat Pulse join
      if (signals.pulseKnown) acc.community_known_count += 1;
      if (signals.pulseRare) acc.community_rare_count += 1;
    }
    // Overlap matrix
    if (inWindow.length >= 2 && inWindow.length <= MAX_COMBINED_SOURCES_PER_DOCUMENT) {
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

const termsInChunks = (field: string, values: string[]) => {
  const chunks: string[][] = [];
  for (let i = 0; i < values.length; i += TERMS_CHUNK_SIZE) {
    chunks.push(values.slice(i, i + TERMS_CHUNK_SIZE));
  }
  return chunks.length === 1
    ? { terms: { [field]: chunks[0] } }
    : { bool: { should: chunks.map((chunk) => ({ terms: { [field]: chunk } })), minimum_should_match: 1 } };
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
  if (run.availability.huntRunType && run.huntTrueRunIds.length > 0) {
    sightingsAggs.hunt = {
      filter: termsInChunks(`${HUNT_RUN_SIGHTING_ATTRIBUTE}.keyword`, run.huntTrueRunIds),
      aggs: connectionCountAggregation(ids, 'from'),
    };
  }
  // Relationships created after the computation time are counted by the streaming increments only
  const createdBeforeRun = { range: { created_at: { lte: new Date(run.asOf).toISOString() } } };
  const [sightingsData, relationshipsData, containersData] = await Promise.all([
    rawSearch(context, [READ_INDEX_STIX_SIGHTING_RELATIONSHIPS], {
      query: { bool: { filter: [createdBeforeRun, { nested: { path: 'connections', query: { bool: { filter: connectionFilter(ids, 'from') } } } }] } },
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
  ]);
  const sightingsAggregations = sightingsData.aggregations ?? {};
  lookups.sightings = bucketsToMap(sightingsAggregations, ['positive', 'connections', 'matching', 'ids']);
  lookups.negativeSightings = bucketsToMap(sightingsAggregations, ['negative', 'connections', 'matching', 'ids']);
  lookups.platformSightings = bucketsToMap(sightingsAggregations, ['platform', 'connections', 'matching', 'ids']);
  lookups.huntTruePositives = bucketsToMap(sightingsAggregations, ['hunt', 'connections', 'matching', 'ids']);
  const relationshipsAggregations = relationshipsData.aggregations ?? {};
  lookups.relationshipReferences = bucketsToMap(relationshipsAggregations, ['all', 'connections', 'matching', 'ids']);
  lookups.relationshipIncidents = bucketsToMap(relationshipsAggregations, ['incidents', 'connections', 'matching', 'ids']);
  const containersAggregations = containersData.aggregations ?? {};
  lookups.containerReferences = bucketsToMap(containersAggregations, ['all']);
  lookups.containerIncidents = bucketsToMap(containersAggregations, ['incidents', 'ids']);
  return lookups;
};

const resolveFalsePositiveLabelIds = async (context: AuthContext, labels: string[]): Promise<Set<string>> => {
  if (labels.length === 0) {
    return new Set();
  }
  const data = await rawSearch(context, [READ_INDEX_STIX_META_OBJECTS], {
    query: { bool: { filter: [{ term: { 'entity_type.keyword': ENTITY_TYPE_LABEL } }, { terms: { 'value.keyword': labels } }] } },
    _source: ['internal_id'],
  }, 1000);
  return new Set((data.hits?.hits ?? []).map((hit: any) => hit._source.internal_id as string));
};

/**
 * Every hit of a query, page by page in internal id order, so that no result is dropped past a page size.
 */
const searchAllHits = async (context: AuthContext, index: string[], query: Record<string, unknown>, source: string[], onHits: (hits: any[]) => boolean | void) => {
  let searchAfter: unknown[] | undefined;
  let hasMore = true;
  while (hasMore) {
    const data = await rawSearch(context, index, {
      query,
      _source: source,
      sort: [{ 'internal_id.keyword': 'asc' }],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    }, SCAN_PAGE_SIZE);
    const hits = data.hits?.hits ?? [];
    hasMore = onHits(hits) !== false && hits.length === SCAN_PAGE_SIZE;
    searchAfter = hits.length > 0 ? hits[hits.length - 1].sort : searchAfter;
  }
};

const resolvePirFlaggedIds = async (context: AuthContext, asOf: number): Promise<Set<string>> => {
  const flagged = new Set<string>();
  // PIR links created after the computation time are counted by the streaming increments only
  const query = { bool: { filter: [{ term: { 'entity_type.keyword': RELATION_IN_PIR } }, { range: { created_at: { lte: new Date(asOf).toISOString() } } }] } };
  await searchAllHits(context, [READ_INDEX_INTERNAL_RELATIONSHIPS], query, ['connections.internal_id', 'connections.role'], (hits) => {
    hits.forEach((hit: any) => {
      (hit._source.connections ?? [])
        .filter((connection: { role: string }) => connection.role?.endsWith('_from'))
        .forEach((connection: { internal_id: string }) => flagged.add(connection.internal_id));
    });
    return flagged.size < MAX_PIR_FLAGGED_IDS;
  });
  return flagged;
};

const searchHuntTrueRunIds = async (context: AuthContext, huntRunType: string, filters: Record<string, unknown>[]): Promise<string[]> => {
  const runIds: string[] = [];
  const query = {
    bool: {
      filter: [
        { term: { 'entity_type.keyword': huntRunType } },
        { term: { 'verdict.keyword': HUNT_VERDICT_TRUE_POSITIVE } },
        ...filters,
      ],
    },
  };
  await searchAllHits(context, [READ_INDEX_INTERNAL_OBJECTS], query, ['internal_id'], (hits) => {
    hits.forEach((hit: any) => runIds.push(hit._source.internal_id as string));
  });
  return runIds;
};

/**
 * True positive hunt runs updated in the scorecard range and before the computation time: a verdict given after it
 * is counted by the streaming increments.
 */
const resolveHuntTrueRunIds = async (context: AuthContext, huntRunType: string | null, since: number, asOf: number): Promise<string[]> => {
  if (!huntRunType) {
    return [];
  }
  return searchHuntTrueRunIds(context, huntRunType, [{ range: { updated_at: { gte: new Date(since).toISOString(), lte: new Date(asOf).toISOString() } } }]);
};

/**
 * The hunt runs (innovation 01), among the given ones, whose verdict is a true positive.
 */
export const findTrueHuntRunIds = async (context: AuthContext, huntRunType: string | null, runIds: string[]): Promise<string[]> => {
  if (!huntRunType || runIds.length === 0) {
    return [];
  }
  return searchHuntTrueRunIds(context, huntRunType, [termsInChunks('internal_id.keyword', runIds)]);
};

export interface HuntRunSighting {
  runId: string;
  objectId: string;
}

/**
 * Every sighting that hunt runs (innovation 01) attached to their run id, with the object each one sighted.
 */
export const findHuntRunSightings = async (context: AuthContext, runIds: string[]): Promise<HuntRunSighting[]> => {
  if (runIds.length === 0) {
    return [];
  }
  const sightings: HuntRunSighting[] = [];
  const query = termsInChunks(`${HUNT_RUN_SIGHTING_ATTRIBUTE}.keyword`, runIds);
  await searchAllHits(context, [READ_INDEX_STIX_SIGHTING_RELATIONSHIPS], query, [HUNT_RUN_SIGHTING_ATTRIBUTE, 'connections.internal_id', 'connections.role'], (hits) => {
    hits.forEach((hit: any) => (hit._source.connections ?? [])
      .filter((connection: { role: string }) => connection.role?.endsWith('_from'))
      .forEach((connection: { internal_id: string }) => sightings.push({ runId: hit._source[HUNT_RUN_SIGHTING_ATTRIBUTE] as string, objectId: connection.internal_id })));
  });
  return sightings;
};

export const prepareRunLookups = async (context: AuthContext, settings: SourceIntelligenceSettings, enterprise: boolean, asOf: number): Promise<RunLookups> => {
  const availability = resolveSoftJoinAvailability();
  const maxDays = Math.max(...SCORECARD_PERIODS.map((period) => SCORECARD_PERIOD_DAYS[period]));
  const [falsePositiveLabelIds, pirFlaggedIds, huntTrueRunIds] = await Promise.all([
    resolveFalsePositiveLabelIds(context, settings.false_positive_labels),
    enterprise ? resolvePirFlaggedIds(context, asOf) : Promise.resolve(null),
    resolveHuntTrueRunIds(context, availability.huntRunType, asOf - maxDays * DAY_MS, asOf),
  ]);
  return { asOf, falsePositiveLabelIds, pirFlaggedIds, huntTrueRunIds, availability };
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
  PROVENANCE_ATTRIBUTE,
  `${PULSE_INFORMATION_ATTRIBUTE}.prevalence_bucket`,
];

export const buildScanQuery = (asOf: number, windowStart: number, mode: ProvenanceMode) => {
  const startIso = new Date(windowStart).toISOString();
  const should: unknown[] = [
    { range: { updated_at: { gte: startIso } } },
    { range: { created_at: { gte: startIso } } },
  ];
  if (mode === 'assertions') {
    should.push({ range: { [PROVENANCE_LAST_ASSERTED_AT]: { gte: startIso } } });
  }
  return {
    bool: {
      filter: [{ range: { created_at: { lte: new Date(asOf).toISOString() } } }],
      should,
      minimum_should_match: 1,
    },
  };
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
  const query = buildScanQuery(state.asOf, state.asOf - maxDays * DAY_MS, run.availability.provenance);
  const now = Date.now();
  let searchAfter: unknown[] | undefined;
  for (;;) {
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
    }, SCAN_PAGE_SIZE);
    const hits = data.hits?.hits ?? [];
    if (hits.length === 0) {
      break;
    }
    const docs: ScanDocument[] = hits.map((hit: any) => hit._source as ScanDocument);
    const pageLookups = await fetchPageLookups(context, docs, run);
    for (let i = 0; i < docs.length; i += 1) {
      await doYield();
      const signals = computeDocumentSignals(docs[i], pageLookups, run, now);
      processDocument(state, docs[i], resolver, signals, settings);
    }
    state.scanned += hits.length;
    if (state.scanned >= settings.max_scan_objects) {
      state.truncated = true;
      logApp.warn('[OPENCTI-MODULE] Source intelligence scan truncated, increase max_scan_objects to cover the whole period', {
        scanned: state.scanned,
        max_scan_objects: settings.max_scan_objects,
      });
      break;
    }
    if (hits.length < SCAN_PAGE_SIZE) {
      break;
    }
    searchAfter = hits[hits.length - 1].sort;
  }
};

// region scorecard documents
export const buildOverlapShares = (pairs: Map<string, number>, sourceId: string, volume: number, top: number): SourceOverlapShare[] => {
  if (volume <= 0) {
    return [];
  }
  const shares: SourceOverlapShare[] = [];
  pairs.forEach((count, key) => {
    const [a, b] = key.split('|');
    if (a === sourceId || b === sourceId) {
      shares.push({ source_id: a === sourceId ? b : a, shared_count: count, share: round(Math.min(1, count / volume)) });
    }
  });
  return shares.sort((x, y) => y.shared_count - x.shared_count || x.source_id.localeCompare(y.source_id)).slice(0, top);
};

export const buildScorecardDocuments = (
  state: ComputeState,
  sources: BasicStoreEntitySource[],
  settings: SourceIntelligenceSettings,
  options: { enterprise: boolean; availability: SoftJoinAvailability; live: boolean; snapshot: boolean },
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
        hunt_true_positives_count: acc.hunt_true_positives_count,
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
        community_known_count: options.availability.pulse ? acc.community_known_count : null,
        community_uniqueness: options.availability.pulse ? ratio(acc.community_rare_count, acc.community_known_count) : null,
        overlap: buildOverlapShares(periodPairs, source.internal_id, acc.volume_total, settings.overlap_top),
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
        snapshot_date: snapshotDate,
        computed_at: computedAt,
        created_at: computedAt,
        updated_at: computedAt,
        provenance_mode: options.availability.provenance,
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
