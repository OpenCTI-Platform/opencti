import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_SOURCE = 'Source';
export const ENTITY_TYPE_SOURCE_SCORECARD = 'SourceScorecard';
export const ENTITY_TYPE_COLLECTION_GAP = 'CollectionGap';
export const ENTITY_TYPE_SOURCE_RECOMMENDATION = 'SourceRecommendation';

export const SOURCE_INTELLIGENCE_MANAGER_ID = 'SOURCE_INTELLIGENCE_MANAGER';

// region enums
export const SOURCE_KIND_CONNECTOR = 'connector';
export const SOURCE_KIND_INGESTION_FEED = 'ingestion_feed';
export const SOURCE_KIND_AUTHOR = 'author';
export const SOURCE_KIND_MANUAL = 'manual';
export const SOURCE_KINDS = [SOURCE_KIND_CONNECTOR, SOURCE_KIND_INGESTION_FEED, SOURCE_KIND_AUTHOR, SOURCE_KIND_MANUAL] as const;
export type SourceKindValue = typeof SOURCE_KINDS[number];

export const SOURCE_COST_PERIODS = ['month', 'quarter', 'year'] as const;
export type SourceCostPeriodValue = typeof SOURCE_COST_PERIODS[number];

export const SCORECARD_PERIOD_7D = 'LAST_7_DAYS';
export const SCORECARD_PERIOD_30D = 'LAST_30_DAYS';
export const SCORECARD_PERIOD_90D = 'LAST_90_DAYS';
export const SCORECARD_PERIODS = [SCORECARD_PERIOD_7D, SCORECARD_PERIOD_30D, SCORECARD_PERIOD_90D] as const;
export type ScorecardPeriodValue = typeof SCORECARD_PERIODS[number];
export const SCORECARD_PERIOD_DAYS: Record<ScorecardPeriodValue, number> = {
  [SCORECARD_PERIOD_7D]: 7,
  [SCORECARD_PERIOD_30D]: 30,
  [SCORECARD_PERIOD_90D]: 90,
};
// Period used to denormalize the latest KPIs on the Source (leaderboard sorting) and to run the recommendation rules
export const REFERENCE_SCORECARD_PERIOD: ScorecardPeriodValue = SCORECARD_PERIOD_30D;

export const RECOMMENDATION_RAISE_CONFIDENCE = 'raise_confidence';
export const RECOMMENDATION_LOWER_CONFIDENCE = 'lower_confidence';
export const RECOMMENDATION_ADD_DECAY_RULE = 'add_decay_rule';
export const RECOMMENDATION_CHANGE_SCHEDULE = 'change_schedule';
export const RECOMMENDATION_ADD_DENY_LIST = 'add_deny_list';
export const RECOMMENDATION_QUARANTINE = 'quarantine';
export const RECOMMENDATION_RETIRE = 'retire';
export const RECOMMENDATION_ADD_CONNECTOR = 'add_connector';
export const RECOMMENDATION_KINDS = [
  RECOMMENDATION_RAISE_CONFIDENCE,
  RECOMMENDATION_LOWER_CONFIDENCE,
  RECOMMENDATION_ADD_DECAY_RULE,
  RECOMMENDATION_CHANGE_SCHEDULE,
  RECOMMENDATION_ADD_DENY_LIST,
  RECOMMENDATION_QUARANTINE,
  RECOMMENDATION_RETIRE,
  RECOMMENDATION_ADD_CONNECTOR,
] as const;
export type RecommendationKindValue = typeof RECOMMENDATION_KINDS[number];

export const RECOMMENDATION_STATUS_PROPOSED = 'proposed';
export const RECOMMENDATION_STATUS_APPLIED = 'applied';
export const RECOMMENDATION_STATUS_DISMISSED = 'dismissed';
export const RECOMMENDATION_STATUS_REVERTED = 'reverted';
export const RECOMMENDATION_STATUS_FAILED = 'failed';
// Recorded before the side effect of an apply runs: a recommendation whose outcome could not be recorded stays in it
export const RECOMMENDATION_STATUS_APPLYING = 'applying';
// Recorded before the side effect of a revert runs: a revert whose outcome could not be recorded stays in it
export const RECOMMENDATION_STATUS_REVERTING = 'reverting';
// A failed recommendation stays the live entry of its fingerprint, to be retried, never proposed again beside it
export const ACTIVE_RECOMMENDATION_STATUSES = [
  RECOMMENDATION_STATUS_PROPOSED,
  RECOMMENDATION_STATUS_APPLYING,
  RECOMMENDATION_STATUS_APPLIED,
  RECOMMENDATION_STATUS_REVERTING,
  RECOMMENDATION_STATUS_FAILED,
] as const;
export const RECOMMENDATION_STATUSES = [
  RECOMMENDATION_STATUS_PROPOSED,
  RECOMMENDATION_STATUS_APPLYING,
  RECOMMENDATION_STATUS_APPLIED,
  RECOMMENDATION_STATUS_REVERTING,
  RECOMMENDATION_STATUS_DISMISSED,
  RECOMMENDATION_STATUS_REVERTED,
  RECOMMENDATION_STATUS_FAILED,
] as const;
export type RecommendationStatusValue = typeof RECOMMENDATION_STATUSES[number];
// endregion

// region Source
export interface SourceCost {
  amount: number;
  currency: string;
  period: SourceCostPeriodValue;
}

// Latest reference-period KPIs, denormalized on the Source so the leaderboard can sort and paginate server side
export interface SourceLatestKpis {
  latest_value_score?: number | null;
  latest_volume?: number | null;
  latest_unique_contribution?: number | null;
  latest_corroboration_rate?: number | null;
  latest_lead_time_hours?: number | null;
  latest_accuracy?: number | null;
  latest_relevance?: number | null;
  latest_impact_score?: number | null;
  latest_noise?: number | null;
  latest_freshness_hours?: number | null;
  latest_cost_per_actionable?: number | null;
}

interface SourceFields extends SourceLatestKpis {
  name: string;
  source_kind: SourceKindValue;
  ref_id: string;
  ref_type?: string;
  // Users writing on behalf of the source (connector user, feed user, analyst), used to attribute the knowledge
  source_user_ids?: string[];
  source_cost?: SourceCost | null;
  tags?: string[];
  owner_id?: string | null;
  enabled: boolean;
  quarantined?: boolean;
  quarantine_draft_id?: string | null;
  last_computed_at?: string | null;
}

export interface BasicStoreEntitySource extends BasicStoreEntity, SourceFields {}
export interface StoreEntitySource extends StoreEntity, SourceFields {}
export interface StixSource extends StixObject {
  name: string;
  description?: string;
  source_kind: string;
  ref_id: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Scorecard
export interface SourceOverlapShare {
  source_id: string;
  shared_count: number;
  share: number;
}

export interface SourceScorecardMetrics {
  // Volume
  volume_total: number;
  volume_entities: number;
  volume_relationships: number;
  volume_indicators: number;
  volume_observables: number;
  new_objects: number;
  volume_last_day: number;
  // Uniqueness and corroboration
  unique_count: number;
  unique_contribution: number;
  corroborated_count: number;
  corroboration_rate: number;
  // Lead time
  shared_count: number;
  lead_time_hours: number | null;
  first_reporter_share: number | null;
  // Accuracy
  evaluated_count: number;
  revoked_count: number;
  negative_sightings_count: number;
  false_positive_count: number;
  decay_excluded_count: number;
  accuracy: number | null;
  // Relevance (Enterprise Edition)
  pir_matched_count: number | null;
  relevance: number | null;
  // Impact
  sightings_count: number;
  security_platform_sightings_count: number;
  incidents_count: number;
  impact_score: number;
  // Noise
  unreferenced_count: number;
  unsighted_count: number;
  expired_count: number;
  noise_count: number;
  noise: number | null;
  // Freshness
  source_last_asserted_at: string | null;
  freshness_hours: number | null;
  median_latency_hours: number | null;
  // Cost
  actionable_count: number;
  cost_per_actionable_object: number | null;
  cost_currency: string | null;
  // Synthesis
  value_score: number;
  overlap: SourceOverlapShare[];
}

export interface StoreSourceScorecard extends SourceScorecardMetrics {
  _index?: string;
  id: string;
  internal_id: string;
  standard_id: string;
  entity_type: typeof ENTITY_TYPE_SOURCE_SCORECARD;
  base_type: 'ENTITY';
  parent_types: string[];
  source_id: string;
  source_kind: SourceKindValue;
  source_name: string;
  scorecard_period: ScorecardPeriodValue;
  period_start: string;
  period_end: string;
  scorecard_date: string;
  computed_at: string;
  created_at: string;
  updated_at: string;
  is_live: boolean;
  // Last stream event the live scorecard counts
  live_stream_event_id?: string;
}
// endregion

// region Collection gap
export interface CollectionGapCoveringSource {
  source_id: string;
  matched_count: number;
  share: number;
}

export interface CollectionGapRecommendedConnector {
  slug: string;
  title: string;
  short_description?: string | null;
  origin: 'hub' | 'catalog';
  score: number;
  catalog_id?: string | null;
  contract_image?: string | null;
  manager_supported: boolean;
  verified?: boolean | null;
  deployed: boolean;
  coverage_inferred?: boolean | null;
  matched_object_types: string[];
  matched_sectors: string[];
  matched_regions: string[];
}

// partial: XTM Hub matched more integrations than it ranks, its matches are combined with the local catalog
export const HUB_CATALOG_STATUSES = ['ok', 'partial', 'unreachable', 'not_registered', 'error'] as const;
export type HubCatalogStatus = typeof HUB_CATALOG_STATUSES[number];

interface CollectionGapFields {
  name: string;
  pir_id: string;
  criterion_index: number;
  criterion_key: string;
  criterion_filters: string;
  criterion_weight: number;
  criterion_label: string;
  gap_coverage_score: number;
  is_gap: boolean;
  matched_relationships: number;
  recent_relationships: number;
  distinct_sources: number;
  covering_sources: CollectionGapCoveringSource[];
  object_types: string[];
  sectors: string[];
  regions: string[];
  recommended_connectors: CollectionGapRecommendedConnector[];
  hub_status: HubCatalogStatus;
  computed_at: string;
}
export interface BasicStoreEntityCollectionGap extends BasicStoreEntity, CollectionGapFields {}
export interface StoreEntityCollectionGap extends StoreEntity, CollectionGapFields {}
export interface StixCollectionGap extends StixObject {
  name: string;
  pir_id: string;
  coverage_score: number;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Recommendation
interface SourceRecommendationFields {
  name: string;
  recommendation_kind: RecommendationKindValue;
  recommendation_status: RecommendationStatusValue;
  source_id?: string | null;
  fingerprint: string;
  rationale: string;
  // JSON payload describing the target of the action (validated per kind)
  payload: string;
  // JSON snapshot of the metrics that triggered the recommendation
  recommendation_evidence: string;
  // JSON list of the author sources its texts name ({ ref_id, name }), with every name the texts were written with
  named_authors?: string | null;
  // JSON snapshot of the state before apply, used to revert
  revert_payload?: string | null;
  apply_result?: string | null;
  error_message?: string | null;
  autonomous?: boolean;
  collection_gap_id?: string | null;
  pir_id?: string | null;
  applied_by_id?: string | null;
  applied_at?: string | null;
  reverted_by_id?: string | null;
  reverted_at?: string | null;
  dismissed_by_id?: string | null;
  dismissed_at?: string | null;
  dismiss_reason?: string | null;
  proposed_at: string;
}
export interface BasicStoreEntitySourceRecommendation extends BasicStoreEntity, SourceRecommendationFields {}
export interface StoreEntitySourceRecommendation extends StoreEntity, SourceRecommendationFields {}
export interface StixSourceRecommendation extends StixObject {
  name: string;
  recommendation_kind: string;
  recommendation_status: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
