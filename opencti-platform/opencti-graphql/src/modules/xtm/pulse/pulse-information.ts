import type { AuthContext } from '../../../types/user';
import { BULK_TIMEOUT, elBulk, elRawUpdateByQuery } from '../../../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../database/utils';
import { logApp } from '../../../config/conf';
import { PulsePrevalence } from '../../../generated/graphql';
import {
  PULSE_ATTRIBUTE_FIRST_SEEN,
  PULSE_ATTRIBUTE_INFORMATION,
  PULSE_ATTRIBUTE_KEYS,
  PULSE_ATTRIBUTE_PREVALENCE,
  PULSE_ATTRIBUTE_SECTOR_TREND,
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

// Share of the community that does not hold the object, 100 when fewer platforms than the anonymity threshold do.
const UNIQUENESS_BY_PREVALENCE: Record<PulsePrevalenceValue, number> = {
  [PulsePrevalence.Rare]: 75,
  [PulsePrevalence.Uncommon]: 50,
  [PulsePrevalence.Common]: 25,
  [PulsePrevalence.Widespread]: 0,
};
const UNPUBLISHED_UNIQUENESS = 100;

export interface PulseCombinedInformation {
  published: boolean;
  prevalence: PulsePrevalenceValue;
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
      prevalence: PulsePrevalence.Rare,
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

const toDayDate = (day: string | null) => (day ? `${day}T00:00:00.000Z` : null);

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
    [PULSE_ATTRIBUTE_INFORMATION]: stored,
  };
};

// An object that left the digest loses its preview signal; its local keys stay.
export const PULSE_PREVIEW_CLEARED_DOCUMENT: Record<string, unknown> = {
  [PULSE_ATTRIBUTE_PREVALENCE]: null,
  [PULSE_ATTRIBUTE_TREND]: null,
  [PULSE_ATTRIBUTE_SECTOR_TREND]: null,
  [PULSE_ATTRIBUTE_FIRST_SEEN]: null,
  [PULSE_ATTRIBUTE_UNIQUENESS]: null,
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

const CLEAR_NETWORK_SCRIPT = [
  PULSE_ATTRIBUTE_PREVALENCE,
  PULSE_ATTRIBUTE_TREND,
  PULSE_ATTRIBUTE_SECTOR_TREND,
  PULSE_ATTRIBUTE_FIRST_SEEN,
  PULSE_ATTRIBUTE_UNIQUENESS,
  PULSE_ATTRIBUTE_INFORMATION,
].map((attribute) => `ctx._source.remove('${attribute}');`).join(' ');

// Removes every network statistic from the entities, when reading is turned off: the local keys stay.
export const clearPulseNetworkInformation = async () => {
  const result = await elRawUpdateByQuery({
    index: READ_INDEX_STIX_DOMAIN_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    wait_for_completion: true,
    body: {
      script: { source: CLEAR_NETWORK_SCRIPT, lang: 'painless' },
      query: { exists: { field: `${PULSE_ATTRIBUTE_INFORMATION}.updated_at` } },
    },
  });
  logApp.info('[THREAT PULSE] Network information cleared from entities', { updated: result?.updated });
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
