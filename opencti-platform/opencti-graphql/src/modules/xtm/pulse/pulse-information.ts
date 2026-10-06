import type { AuthContext } from '../../../types/user';
import { BULK_TIMEOUT, elBulk, elRawUpdateByQuery } from '../../../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../database/utils';
import { buildRefRelationSearchKey } from '../../../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import { logApp } from '../../../config/conf';
import { PulseAccess, PulsePrevalence } from '../../../generated/graphql';
import { isPulseContributable, type PulseMarkingPolicy } from './pulse-settings';
import {
  PULSE_ATTRIBUTE_FIRST_SEEN,
  PULSE_ATTRIBUTE_INFORMATION,
  PULSE_ATTRIBUTE_KEYS,
  PULSE_ATTRIBUTE_PREVALENCE,
  PULSE_ATTRIBUTE_SECTOR_TREND,
  PULSE_ATTRIBUTE_PREVALENCE_RANK,
  PULSE_ATTRIBUTE_TREND,
  PULSE_ATTRIBUTE_UNIQUENESS,
  PULSE_PREVALENCE_VALUES,
  type BasicStorePulseEntity,
  type PulseHubLookupResult,
  type PulsePrevalenceValue,
  type PulseStoredInformation,
  type PulseTrendValue,
} from './pulse-types';

const PLATFORM_BUCKET_ORDER = ['5-9', '10-24', '25-49', '50-99', '100-249', '250+'];

const bucketRank = (bucket: string | null | undefined) => (bucket ? PLATFORM_BUCKET_ORDER.indexOf(bucket) : -1);

const prevalenceRank = (prevalence: PulsePrevalenceValue | null | undefined) => (prevalence ? PULSE_PREVALENCE_VALUES.indexOf(prevalence) : -1);

// Share of the community that does not hold the object. 100 is reserved for objects fewer platforms than the anonymity
// threshold hold - published objects go from 0 to 75 - so the indexed field and the STIX extension tell them apart.
const UNIQUENESS_BY_PREVALENCE: Record<PulsePrevalenceValue, number> = {
  [PulsePrevalence.Rare]: 75,
  [PulsePrevalence.Uncommon]: 50,
  [PulsePrevalence.Common]: 25,
  [PulsePrevalence.Widespread]: 0,
};
const UNPUBLISHED_UNIQUENESS = 100;

export interface PulseCombinedInformation {
  published: boolean;
  // Null below the anonymity threshold: "rare" is a published bucket, never the absence of a published signal.
  prevalence: PulsePrevalenceValue | null;
  platformsBucket: string | null;
  firstSeenNetwork: string | null;
  lastSeenNetwork: string | null;
  trend: PulseTrendValue | null;
  trendSeries: number[];
  sectorTrend: PulseTrendValue | null;
  sectorPlatformsBucket: string | null;
  communityUniqueness: number;
}

const minDate = (dates: Array<string | null>) => dates.filter((date): date is string => !!date).sort()[0] ?? null;
const maxDate = (dates: Array<string | null>) => dates.filter((date): date is string => !!date).sort().reverse()[0] ?? null;

// An object with several keys (a threat and its aliases) takes the signal of its most prevalent published key.
export const combinePulseLookups = (results: PulseHubLookupResult[]): PulseCombinedInformation => {
  const published = results.filter((result) => result.published);
  if (published.length === 0) {
    return {
      published: false,
      prevalence: null,
      platformsBucket: null,
      firstSeenNetwork: null,
      lastSeenNetwork: null,
      trend: null,
      trendSeries: [],
      sectorTrend: null,
      sectorPlatformsBucket: null,
      communityUniqueness: UNPUBLISHED_UNIQUENESS,
    };
  }
  const [main] = [...published].sort((a, b) => (bucketRank(b.platforms_bucket) - bucketRank(a.platforms_bucket))
    || (prevalenceRank(b.prevalence_bucket) - prevalenceRank(a.prevalence_bucket)));
  const prevalence = main.prevalence_bucket ?? PulsePrevalence.Rare;
  const withSector = published.filter((result) => result.sector_trend !== null)
    .sort((a, b) => bucketRank(b.sector_platforms_bucket) - bucketRank(a.sector_platforms_bucket));
  return {
    published: true,
    prevalence,
    platformsBucket: main.platforms_bucket,
    firstSeenNetwork: minDate(published.map((result) => result.first_seen_network)),
    lastSeenNetwork: maxDate(published.map((result) => result.last_seen_network)),
    trend: main.trend,
    trendSeries: main.trend_series ?? [],
    sectorTrend: withSector[0]?.sector_trend ?? null,
    sectorPlatformsBucket: withSector[0]?.sector_platforms_bucket ?? null,
    communityUniqueness: UNIQUENESS_BY_PREVALENCE[prevalence],
  };
};

export const toDayDate = (day: string | null) => (day ? `${day}T00:00:00.000Z` : null);

// 0 below the anonymity threshold, then 1 (rare) to 4 (widespread): one sort key for preview and full documents.
export const pulsePrevalenceRank = (published: boolean, prevalence: PulsePrevalenceValue | null) => (published && prevalence ? prevalenceRank(prevalence) + 1 : 0);

export const buildPulseDocument = (keys: string[], information: PulseCombinedInformation, updatedAt: Date): Record<string, unknown> => {
  const stored: PulseStoredInformation = {
    published: information.published,
    platforms_bucket: information.platformsBucket,
    last_seen_network: toDayDate(information.lastSeenNetwork),
    trend_series: information.trendSeries,
    sector_platforms_bucket: information.sectorPlatformsBucket,
    updated_at: updatedAt.toISOString(),
  };
  return {
    [PULSE_ATTRIBUTE_KEYS]: keys,
    [PULSE_ATTRIBUTE_PREVALENCE]: information.prevalence,
    [PULSE_ATTRIBUTE_TREND]: information.trend,
    [PULSE_ATTRIBUTE_SECTOR_TREND]: information.sectorTrend,
    [PULSE_ATTRIBUTE_FIRST_SEEN]: toDayDate(information.firstSeenNetwork),
    [PULSE_ATTRIBUTE_UNIQUENESS]: information.communityUniqueness,
    [PULSE_ATTRIBUTE_PREVALENCE_RANK]: pulsePrevalenceRank(information.published, information.prevalence),
    [PULSE_ATTRIBUTE_INFORMATION]: stored,
  };
};

export interface PulsePreviewSignal {
  prevalence: PulsePrevalenceValue;
  trend: PulseTrendValue;
}

// An object with several keys found in the digest takes the signal of its most prevalent key.
export const combinePulsePreviewSignals = (signals: PulsePreviewSignal[]): PulsePreviewSignal | null => {
  return [...signals].sort((a, b) => prevalenceRank(b.prevalence) - prevalenceRank(a.prevalence))[0] ?? null;
};

// The preview carries the coarse signal of the digest only: no platforms range, no dates, no series, no sector trend.
export const buildPulsePreviewDocument = (keys: string[], signal: PulsePreviewSignal, updatedAt: Date): Record<string, unknown> => {
  const stored: PulseStoredInformation = { published: true, preview: true, updated_at: updatedAt.toISOString() };
  return {
    [PULSE_ATTRIBUTE_KEYS]: keys,
    [PULSE_ATTRIBUTE_PREVALENCE]: signal.prevalence,
    [PULSE_ATTRIBUTE_TREND]: signal.trend,
    [PULSE_ATTRIBUTE_SECTOR_TREND]: null,
    [PULSE_ATTRIBUTE_FIRST_SEEN]: null,
    [PULSE_ATTRIBUTE_UNIQUENESS]: null,
    [PULSE_ATTRIBUTE_PREVALENCE_RANK]: pulsePrevalenceRank(true, signal.prevalence),
    [PULSE_ATTRIBUTE_INFORMATION]: stored,
  };
};

// An object that left the digest loses its preview signal, and an object that became restricted or carries an excluded
// marking loses its community statistics; its local keys stay.
export const PULSE_PREVIEW_CLEARED_DOCUMENT: Record<string, unknown> = {
  [PULSE_ATTRIBUTE_PREVALENCE]: null,
  [PULSE_ATTRIBUTE_TREND]: null,
  [PULSE_ATTRIBUTE_SECTOR_TREND]: null,
  [PULSE_ATTRIBUTE_FIRST_SEEN]: null,
  [PULSE_ATTRIBUTE_UNIQUENESS]: null,
  [PULSE_ATTRIBUTE_PREVALENCE_RANK]: null,
  [PULSE_ATTRIBUTE_INFORMATION]: null,
};

export interface PulseDocumentUpdate {
  entity: Pick<BasicStorePulseEntity, '_index' | 'internal_id'>;
  doc: Record<string, unknown>;
}

// Network data is a side channel: written directly in the index, it creates no stream event, no history and does not
// move updated_at.
export const writePulseDocuments = async (context: AuthContext, updates: PulseDocumentUpdate[]) => {
  if (updates.length === 0) {
    return;
  }
  const body = updates.flatMap(({ entity, doc }) => [
    { update: { _index: entity._index, _id: entity.internal_id, retry_on_conflict: 5 } },
    { doc },
  ]);
  await elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body });
};

const PULSE_NETWORK_ATTRIBUTES = [
  PULSE_ATTRIBUTE_PREVALENCE,
  PULSE_ATTRIBUTE_TREND,
  PULSE_ATTRIBUTE_SECTOR_TREND,
  PULSE_ATTRIBUTE_FIRST_SEEN,
  PULSE_ATTRIBUTE_UNIQUENESS,
  PULSE_ATTRIBUTE_PREVALENCE_RANK,
  PULSE_ATTRIBUTE_INFORMATION,
];

const CLEAR_NETWORK_SCRIPT = [
  'boolean changed = false;',
  'for (String attribute : params.attributes) { if (ctx._source.containsKey(attribute)) { ctx._source.remove(attribute); changed = true; } }',
  "if (!changed) { ctx.op = 'noop'; }",
].join(' ');

// The objects a more restrictive configuration takes out: those of a removed scope, those with a newly excluded marking.
export interface PulseClearScope {
  entityTypes: string[];
  markingIds: string[];
}

// Removes every network statistic from the entities (all of them, or only those of *scope*): the local keys stay.
// pulse_information is not indexed: the documents are found through the indexed network fields written with it (every
// network write sets the prevalence rank). The local keys, which stay, are not searched: an entity already cleared
// is never scanned again.
export const clearPulseNetworkInformation = async (scope?: PulseClearScope) => {
  const indexedFields = PULSE_NETWORK_ATTRIBUTES.filter((attribute) => attribute !== PULSE_ATTRIBUTE_INFORMATION);
  const hasPulseData = { bool: { should: indexedFields.map((field) => ({ exists: { field } })), minimum_should_match: 1 } };
  const affected = scope ? [
    ...(scope.entityTypes.length > 0 ? [{ terms: { 'entity_type.keyword': scope.entityTypes } }] : []),
    ...(scope.markingIds.length > 0 ? [{ terms: { [buildRefRelationSearchKey(RELATION_OBJECT_MARKING)]: scope.markingIds } }] : []),
  ] : [];
  if (scope && affected.length === 0) {
    return 0;
  }
  const query = scope ? { bool: { filter: [hasPulseData, { bool: { should: affected, minimum_should_match: 1 } }] } } : hasPulseData;
  const result = await elRawUpdateByQuery({
    index: READ_INDEX_STIX_DOMAIN_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    wait_for_completion: true,
    body: {
      script: { source: CLEAR_NETWORK_SCRIPT, lang: 'painless', params: { attributes: PULSE_NETWORK_ATTRIBUTES } },
      query,
    },
  });
  logApp.info('[THREAT PULSE] Network information cleared from entities', { updated: result?.updated, scope });
  return result?.updated ?? 0;
};

export const toPulseInformationOutput = (entity: BasicStorePulseEntity) => {
  const information = entity.pulse_information;
  if (!information?.updated_at) {
    return null;
  }
  return {
    published: information.published,
    preview: information.preview === true,
    prevalence: entity.pulse_prevalence ?? null,
    platforms_bucket: information.platforms_bucket ?? null,
    first_seen_network: entity.pulse_first_seen_network ?? null,
    last_seen_network: information.last_seen_network ?? null,
    trend: entity.pulse_trend ?? null,
    trend_series: information.trend_series ?? [],
    sector_trend: entity.pulse_sector_trend ?? null,
    sector_platforms_bucket: information.sector_platforms_bucket ?? null,
    community_uniqueness: entity.pulse_community_uniqueness ?? null,
    updated_at: information.updated_at,
  };
};

export const isPulsePreviewDocument = (entity: BasicStorePulseEntity) => entity.pulse_information?.preview === true;

export interface PulseFieldPolicy {
  access: PulseAccess;
  scopes: string[];
  // Only read for the full experience: the preview signal is local and covers every object type in scope.
  markingPolicy: PulseMarkingPolicy | null;
}

// What an object shows of the community data under the current access, whatever a cleanup that failed left in the
// index: nothing out of scope, the preview signal alone while the platform reads the preview, and in the full
// experience nothing for an object excluded from the contribution.
export const visiblePulseInformation = (entity: BasicStorePulseEntity, policy: PulseFieldPolicy) => {
  if (!policy.scopes.includes(entity.entity_type)) {
    return null;
  }
  if (policy.access === PulseAccess.Preview) {
    return isPulsePreviewDocument(entity) ? toPulseInformationOutput(entity) : null;
  }
  if (policy.access === PulseAccess.Full && policy.markingPolicy && isPulseContributable(entity, policy.markingPolicy, policy.scopes)) {
    return toPulseInformationOutput(entity);
  }
  return null;
};

// The network attributes generic filters, aggregations, date histograms and sorts read straight from the index.
export const PULSE_QUERYABLE_ATTRIBUTES = [
  PULSE_ATTRIBUTE_PREVALENCE,
  PULSE_ATTRIBUTE_TREND,
  PULSE_ATTRIBUTE_SECTOR_TREND,
  PULSE_ATTRIBUTE_FIRST_SEEN,
  PULSE_ATTRIBUTE_UNIQUENESS,
  PULSE_ATTRIBUTE_PREVALENCE_RANK,
];

const GRANTED_TO_FIELD = buildRefRelationSearchKey(RELATION_GRANTED_TO);
const MARKING_FIELD = buildRefRelationSearchKey(RELATION_OBJECT_MARKING);

// The objects visiblePulseInformation shows, as a query clause, for the queries reading the network attributes from
// the index. Only full documents carry the community uniqueness, which tells a preview document from a full one.
// A marking unknown to the platform is not tested here: deleting a marking removes it from every object.
export const pulseQueryClause = (policy: PulseFieldPolicy): Record<string, unknown> => {
  const inScope = { terms: { 'entity_type.keyword': policy.scopes } };
  if (policy.access === PulseAccess.Preview) {
    return { bool: { filter: [inScope], must_not: [{ exists: { field: PULSE_ATTRIBUTE_UNIQUENESS } }] } };
  }
  if (policy.access === PulseAccess.Full && policy.markingPolicy) {
    const excluded = [...policy.markingPolicy.excludedMarkingIds];
    return {
      bool: {
        filter: [inScope],
        must_not: [
          { nested: { path: 'restricted_members', query: { exists: { field: 'restricted_members.id' } }, ignore_unmapped: true } },
          { exists: { field: GRANTED_TO_FIELD } },
          ...(excluded.length > 0 ? [{ terms: { [MARKING_FIELD]: excluded } }] : []),
        ],
      },
    };
  }
  return { match_none: {} };
};

// The network attributes the generic lists can order by.
export const PULSE_SORTABLE_ATTRIBUTES = [PULSE_ATTRIBUTE_PREVALENCE_RANK, PULSE_ATTRIBUTE_UNIQUENESS, PULSE_ATTRIBUTE_FIRST_SEEN];

// The same rule for a sort on a network attribute: a value the reader may not see sorts as a missing one, last, and
// the objects stay in the list. The members of an authorized members restriction are nested, read from the source;
// a date sorts by its epoch milliseconds.
const VISIBLE_VALUE_SCRIPT = `
  String field = params.field;
  if (!doc.containsKey(field) || doc[field].size() == 0) { return params.missing; }
  if (!doc.containsKey('entity_type.keyword') || doc['entity_type.keyword'].size() == 0 || !params.scopes.contains(doc['entity_type.keyword'].value)) { return params.missing; }
  def value = params.date ? doc[field].value.toInstant().toEpochMilli() : doc[field].value;
  if (params.access == '${PulseAccess.Preview}') {
    return doc.containsKey('${PULSE_ATTRIBUTE_UNIQUENESS}') && doc['${PULSE_ATTRIBUTE_UNIQUENESS}'].size() > 0 ? params.missing : value;
  }
  if (params.access != '${PulseAccess.Full}') { return params.missing; }
  if (doc.containsKey('${GRANTED_TO_FIELD}') && doc['${GRANTED_TO_FIELD}'].size() > 0) { return params.missing; }
  if (doc.containsKey('${MARKING_FIELD}')) {
    for (def marking : doc['${MARKING_FIELD}']) { if (params.excluded.contains(marking)) { return params.missing; } }
  }
  def members = params['_source']['restricted_members'];
  return members != null && members.size() > 0 ? params.missing : value;
`;

export const pulseVisibleSort = (policy: PulseFieldPolicy, attribute: string, orderMode: 'asc' | 'desc' | null) => {
  const order = orderMode ?? 'asc';
  return {
    _script: {
      type: 'number',
      order,
      script: {
        lang: 'painless',
        source: VISIBLE_VALUE_SCRIPT,
        params: {
          field: attribute,
          date: attribute === PULSE_ATTRIBUTE_FIRST_SEEN,
          access: policy.markingPolicy || policy.access !== PulseAccess.Full ? policy.access : PulseAccess.Off,
          scopes: policy.scopes,
          excluded: [...(policy.markingPolicy?.excludedMarkingIds ?? [])],
          missing: order === 'desc' ? -1 : Number.MAX_SAFE_INTEGER,
        },
      },
    },
  };
};
