import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL } from '../../../schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../indicator/indicator-types';
import { ENTITY_TYPE_VULNERABILITY } from '../../vulnerability/vulnerability-types';
import type { BasicStoreEntity, StoreMarkingDefinition } from '../../../types/store';
import {
  type PulseAccess,
  PulseMode,
  PulsePeriod,
  PulsePrevalence,
  PulseRegionBucket,
  PulseSectorBucket,
  PulseTrend,
  type PulseContributionStats,
  type PulseNetworkStatus,
  type PulsePreviewStats,
} from '../../../generated/graphql';

// Wire values of the Threat Pulse contract shared with the XTM Hub platform API: changing one breaks the Hub API.
export type PulseObjectType = 'indicator' | 'attack_pattern' | 'vulnerability' | 'intrusion_set' | 'malware' | 'tool';
// XTM Hub also accepts 'hunted', which no activity source of this platform produces.
export type PulseEventKind = 'created' | 'sighted' | 'detected' | 'hunted' | 'referenced';
export type PulseModeValue = PulseMode;
export type PulsePrevalenceValue = PulsePrevalence;
export type PulseTrendValue = PulseTrend;
export type PulsePeriodValue = PulsePeriod;
export type PulseSectorBucketValue = PulseSectorBucket;
export type PulseRegionBucketValue = PulseRegionBucket;

export const PULSE_SECTOR_BUCKETS: PulseSectorBucketValue[] = Object.values(PulseSectorBucket);
export const PULSE_REGION_BUCKETS: PulseRegionBucketValue[] = Object.values(PulseRegionBucket);
export const PULSE_EVENT_KINDS: PulseEventKind[] = ['created', 'sighted', 'detected', 'hunted', 'referenced'];
export const PULSE_PREVALENCE_VALUES: PulsePrevalenceValue[] = [PulsePrevalence.Rare, PulsePrevalence.Uncommon, PulsePrevalence.Common, PulsePrevalence.Widespread];
export const PULSE_TREND_VALUES: PulseTrendValue[] = [PulseTrend.Rising, PulseTrend.Stable, PulseTrend.Falling];
export const PULSE_MODE_VALUES: PulseModeValue[] = [PulseMode.Off, PulseMode.Preview, PulseMode.ContributeAndRead];

// Entity types that can contribute to and read from Threat Pulse, with their wire object type.
export const PULSE_OBJECT_TYPE_BY_ENTITY_TYPE: Record<string, PulseObjectType> = {
  [ENTITY_TYPE_INDICATOR]: 'indicator',
  [ENTITY_TYPE_ATTACK_PATTERN]: 'attack_pattern',
  [ENTITY_TYPE_VULNERABILITY]: 'vulnerability',
  [ENTITY_TYPE_INTRUSION_SET]: 'intrusion_set',
  [ENTITY_TYPE_MALWARE]: 'malware',
  [ENTITY_TYPE_TOOL]: 'tool',
};
export const PULSE_SCOPE_ENTITY_TYPES = Object.keys(PULSE_OBJECT_TYPE_BY_ENTITY_TYPE);
export const PULSE_ENTITY_TYPE_BY_OBJECT_TYPE: Record<PulseObjectType, string> = Object.fromEntries(
  Object.entries(PULSE_OBJECT_TYPE_BY_ENTITY_TYPE).map(([entityType, objectType]) => [objectType, entityType]),
) as Record<PulseObjectType, string>;

// Markings that never contribute, whatever the configuration (definition_type:definition, upper case).
export const PULSE_FORCED_EXCLUDED_MARKING_DEFINITIONS = ['TLP:RED', 'TLP:AMBER+STRICT', 'PAP:RED'];

// Version of the consent text an administrator accepts to enable Threat Pulse. Changing the text requires a new version.
export const PULSE_CONSENT_VERSION = '2026-10-1';

// Wire limits shared with XTM Hub.
export const PULSE_MAX_RECORDS_PER_BATCH = 5000;
export const PULSE_MAX_LOOKUP_HASHES = 1000;
export const PULSE_MAX_RECORD_COUNT = 100000;
export const PULSE_MAX_KEYS_PER_OBJECT = 10;
export const PULSE_TREND_SERIES_WEEKS = 12;

export const PULSE_STATUS_ID = 'pulse-status';
export const PULSE_SETTINGS_ID = 'pulse-settings';

// Settings attributes.
export const PULSE_SETTINGS_MODE = 'pulse_mode';
export const PULSE_SETTINGS_SCOPES = 'pulse_scopes';
export const PULSE_SETTINGS_EXCLUDED_MARKINGS = 'pulse_excluded_markings';
export const PULSE_SETTINGS_SECTOR = 'pulse_sector_bucket';
export const PULSE_SETTINGS_REGION = 'pulse_region_bucket';
export const PULSE_SETTINGS_CONSENT_VERSION = 'pulse_consent_version';
export const PULSE_SETTINGS_CONSENT_DATE = 'pulse_consent_date';
export const PULSE_SETTINGS_CONSENT_USER = 'pulse_consent_user_id';
export const PULSE_SETTINGS_KEYS = [
  PULSE_SETTINGS_MODE,
  PULSE_SETTINGS_SCOPES,
  PULSE_SETTINGS_EXCLUDED_MARKINGS,
  PULSE_SETTINGS_SECTOR,
  PULSE_SETTINGS_REGION,
  PULSE_SETTINGS_CONSENT_VERSION,
  PULSE_SETTINGS_CONSENT_DATE,
  PULSE_SETTINGS_CONSENT_USER,
];

// Entity attributes written by the read path without stream events.
export const PULSE_ATTRIBUTE_KEYS = 'pulse_keys';
export const PULSE_ATTRIBUTE_PREVALENCE = 'pulse_prevalence';
export const PULSE_ATTRIBUTE_TREND = 'pulse_trend';
export const PULSE_ATTRIBUTE_SECTOR_TREND = 'pulse_sector_trend';
export const PULSE_ATTRIBUTE_FIRST_SEEN = 'pulse_first_seen_network';
export const PULSE_ATTRIBUTE_UNIQUENESS = 'pulse_community_uniqueness';
// The sort key of the community prevalence, written in preview and full mode: 0 below the anonymity threshold, then
// 1 (rare) to 4 (widespread).
export const PULSE_ATTRIBUTE_PREVALENCE_RANK = 'pulse_prevalence_rank';
export const PULSE_ATTRIBUTE_INFORMATION = 'pulse_information';
export const PULSE_ENTITY_ATTRIBUTES = [
  PULSE_ATTRIBUTE_KEYS,
  PULSE_ATTRIBUTE_PREVALENCE,
  PULSE_ATTRIBUTE_TREND,
  PULSE_ATTRIBUTE_SECTOR_TREND,
  PULSE_ATTRIBUTE_FIRST_SEEN,
  PULSE_ATTRIBUTE_UNIQUENESS,
  PULSE_ATTRIBUTE_PREVALENCE_RANK,
  PULSE_ATTRIBUTE_INFORMATION,
];

export interface PulseSettingsValues {
  mode: PulseModeValue;
  scopes: string[];
  excludedMarkingIds: string[];
  sectorBucket: PulseSectorBucketValue | undefined;
  regionBucket: PulseRegionBucketValue | undefined;
  consentVersion: string | undefined;
  consentDate: Date | undefined;
  consentUserId: string | undefined;
}

// One outbound record: the only shape that ever leaves the platform (hash and counts, never a value).
export interface PulseRecord {
  hash: string;
  object_type: PulseObjectType;
  event_kind: PulseEventKind;
  count: number;
}

export interface PulseBatch {
  // Random UUID drawn once per batch and sent again on every retry: XTM Hub counts a batch once.
  batch_id: string;
  day: string;
  sector_bucket: PulseSectorBucketValue;
  region_bucket: PulseRegionBucketValue;
  records: PulseRecord[];
}

// What a batch adds to the contribution statistics once XTM Hub accepted it. Kept on the platform, never sent.
export interface PulseBatchStats {
  records: number;
  objects: number;
  by_type: Record<string, number>;
}

export interface PulseOutboxItem {
  batch: PulseBatch;
  stats: PulseBatchStats;
  // The privacy policy generation the batch was built under: a batch of an earlier one is never sent.
  policy?: string;
}

// Hub answers (contract section 3).
export interface PulseHubLookupResult {
  hash: string;
  published: boolean;
  prevalence_bucket: PulsePrevalenceValue | null;
  platforms_bucket: string | null;
  first_seen_network: string | null;
  last_seen_network: string | null;
  trend: PulseTrendValue | null;
  trend_series: number[] | null;
  sector_trend: PulseTrendValue | null;
  sector_platforms_bucket: string | null;
}

export interface PulseHubTrendingItem {
  hash: string;
  object_type: PulseObjectType;
  platforms_bucket: string;
  prevalence_bucket: PulsePrevalenceValue;
  trend: PulseTrendValue;
  growth: number;
  // Null when the object reached the anonymity threshold over the period but in no single week: XTM Hub withholds it.
  first_seen_network: string | null;
}

export interface PulseHubTrendingResult {
  day: string;
  period: PulsePeriodValue;
  sector_bucket: PulseSectorBucketValue | null;
  region_bucket: PulseRegionBucketValue | null;
  items: PulseHubTrendingItem[];
}

export interface PulseHubBenchmarkMetric {
  object_type: PulseObjectType;
  event_kind: PulseEventKind;
  // Every sector the platform reported under in the period: compared with network_median.
  platform_count: number;
  // The platform's current sector only: compared with sector_median.
  sector_platform_count: number;
  sector_median: number | null;
  network_median: number | null;
}

export interface PulseHubBenchmarkItem {
  hash: string;
  object_type: PulseObjectType;
  platform_count: number;
  sector_median: number;
  ratio: number;
}

export interface PulseHubBenchmarkResult {
  period: PulsePeriodValue;
  sector_bucket: PulseSectorBucketValue;
  region_bucket: PulseRegionBucketValue;
  sector_platforms_bucket: string | null;
  metrics: PulseHubBenchmarkMetric[];
  top_items: PulseHubBenchmarkItem[];
}

export type PulseHubContributionStatus = 'active' | 'grace' | 'lapsed' | 'none';

export interface PulseHubStatus {
  day: string;
  k_threshold: number;
  retention_months: number;
  contributors_bucket: string;
  read_access: boolean;
  last_contribution_day: string | null;
  contribution_status: PulseHubContributionStatus;
  read_access_until: string | null;
  contribution_window_days: number;
  contribution_grace_days: number;
}

export interface PulseHubDigestItem {
  hash: string;
  object_type: PulseObjectType;
  prevalence_bucket: PulsePrevalenceValue;
  trend: PulseTrendValue;
}

export interface PulseHubDigest {
  day: string;
  sector_bucket: PulseSectorBucketValue | null;
  region_bucket: PulseRegionBucketValue | null;
  items: PulseHubDigestItem[];
  trending: {
    period: PulsePeriodValue;
    locked_count: number;
    items: Array<PulseHubDigestItem & { rank: number }>;
  };
}

// pulse_information stored on scoped entities. `preview` marks the coarse data of the digest (prevalence and trend only).
export interface PulseStoredInformation {
  published: boolean;
  preview?: boolean;
  platforms_bucket?: string | null;
  last_seen_network?: string | null;
  trend_series?: number[];
  sector_platforms_bucket?: string | null;
  updated_at: string;
}

export interface PulseSettingsOutput {
  id: string;
  mode: PulseModeValue;
  access: PulseAccess;
  enabled: boolean;
  readable: boolean;
  hub_registered: boolean;
  consent_version: string;
  consent_accepted_version: string | null;
  consent_date: Date | null;
  consent_user_name: string | null;
  scopes: string[];
  available_scopes: string[];
  excluded_markings: StoreMarkingDefinition[];
  forced_excluded_markings: StoreMarkingDefinition[];
  sector_bucket: PulseSectorBucketValue | null;
  region_bucket: PulseRegionBucketValue | null;
  suggested_sector_bucket: PulseSectorBucketValue;
  suggested_region_bucket: PulseRegionBucketValue;
  contribution: PulseContributionStats;
  preview: PulsePreviewStats;
  network: PulseNetworkStatus;
}

export interface BasicStorePulseEntity extends BasicStoreEntity {
  pulse_keys?: string[];
  pulse_prevalence?: PulsePrevalenceValue;
  pulse_trend?: PulseTrendValue;
  pulse_sector_trend?: PulseTrendValue;
  pulse_first_seen_network?: string;
  pulse_community_uniqueness?: number;
  pulse_prevalence_rank?: number;
  pulse_information?: PulseStoredInformation;
}
