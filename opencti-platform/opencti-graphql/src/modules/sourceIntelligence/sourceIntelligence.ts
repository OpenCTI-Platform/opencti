import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { AttributeDefinition, NumericAttribute } from '../../schema/attribute-definition';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import {
  ENTITY_TYPE_COLLECTION_GAP,
  ENTITY_TYPE_SOURCE,
  ENTITY_TYPE_SOURCE_RECOMMENDATION,
  ENTITY_TYPE_SOURCE_SCORECARD,
  HUB_CATALOG_STATUSES,
  RECOMMENDATION_KINDS,
  RECOMMENDATION_STATUSES,
  SCORECARD_PERIODS,
  SOURCE_COST_PERIODS,
  SOURCE_KINDS,
  type StixCollectionGap,
  type StixSource,
  type StixSourceRecommendation,
  type StoreEntityCollectionGap,
  type StoreEntitySource,
  type StoreEntitySourceRecommendation,
} from './sourceIntelligence-types';
import { convertCollectionGapToStix, convertSourceRecommendationToStix, convertSourceToStix } from './sourceIntelligence-converter';

const numeric = (name: string, label: string, precision: NumericAttribute['precision'], isFilterable = false): NumericAttribute => ({
  name,
  label,
  type: 'numeric',
  precision,
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable,
});

const shortText = (name: string, label: string, opts: { multiple?: boolean; isFilterable?: boolean; mandatory?: boolean } = {}): AttributeDefinition => ({
  name,
  label,
  type: 'string',
  format: 'short',
  mandatoryType: opts.mandatory ? 'internal' : 'no',
  editDefault: false,
  multiple: opts.multiple ?? false,
  upsert: false,
  isFilterable: opts.isFilterable ?? false,
});

const longText = (name: string, label: string): AttributeDefinition => ({
  name, label, type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false,
});

const json = (name: string, label: string): AttributeDefinition => ({
  name, label, type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false,
});

const date = (name: string, label: string, isFilterable = false): AttributeDefinition => ({
  name, label, type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable,
});

const bool = (name: string, label: string, isFilterable = false): AttributeDefinition => ({
  name, label, type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable,
});

// region Source
// Latest reference-period KPIs, sortable and filterable for the leaderboard and the dashboard widgets
export const SOURCE_LATEST_KPI_ATTRIBUTES: NumericAttribute[] = [
  numeric('latest_value_score', 'Latest operational value score', 'float', true),
  numeric('latest_volume', 'Latest volume', 'long', true),
  numeric('latest_unique_contribution', 'Latest unique contribution', 'float', true),
  numeric('latest_corroboration_rate', 'Latest corroboration rate', 'float', true),
  numeric('latest_lead_time_hours', 'Latest lead time (hours)', 'float', true),
  numeric('latest_accuracy', 'Latest accuracy', 'float', true),
  numeric('latest_relevance', 'Latest relevance', 'float', true),
  numeric('latest_impact_score', 'Latest impact score', 'float', true),
  numeric('latest_noise', 'Latest noise', 'float', true),
  numeric('latest_freshness_hours', 'Latest freshness (hours)', 'float', true),
  numeric('latest_cost_per_actionable', 'Latest cost per actionable object', 'float', true),
];

const SOURCE_DEFINITION: ModuleDefinition<StoreEntitySource, StixSource> = {
  type: {
    id: 'source',
    name: ENTITY_TYPE_SOURCE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // One source per kind and referenced element (connector, feed, author identity, analyst user)
      [ENTITY_TYPE_SOURCE]: [{ src: 'source_kind' }, { src: 'ref_id' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'source_kind', label: 'Source kind', type: 'string', format: 'enum', values: [...SOURCE_KINDS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { ...shortText('ref_id', 'Referenced element', { isFilterable: true, mandatory: true }) },
    shortText('ref_type', 'Referenced element type', { isFilterable: true }),
    { name: 'source_user_ids', label: 'Source users', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: false },
    {
      name: 'source_cost',
      label: 'Cost',
      type: 'object',
      format: 'standard',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'amount', label: 'Amount', type: 'numeric', precision: 'float', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'currency', label: 'Currency', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'period', label: 'Period', type: 'string', format: 'enum', values: [...SOURCE_COST_PERIODS], mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      ],
    },
    shortText('tags', 'Tags', { multiple: true, isFilterable: true }),
    { name: 'owner_id', label: 'Owner', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    bool('enabled', 'Enabled', true),
    bool('quarantined', 'Quarantined', true),
    shortText('quarantine_draft_id', 'Quarantine draft'),
    date('last_computed_at', 'Last scorecard computation', true),
    ...SOURCE_LATEST_KPI_ATTRIBUTES,
  ],
  relations: [],
  representative: (stix: StixSource) => stix.name,
  converter_2_1: convertSourceToStix,
};
// endregion

// region Source scorecard (dedicated index, written by the source intelligence manager)
export const SCORECARD_NUMERIC_ATTRIBUTES: NumericAttribute[] = [
  numeric('volume_total', 'Volume', 'long'),
  numeric('volume_entities', 'Entities', 'long'),
  numeric('volume_relationships', 'Relationships', 'long'),
  numeric('volume_indicators', 'Indicators', 'long'),
  numeric('volume_observables', 'Observables', 'long'),
  numeric('new_objects', 'New objects', 'long'),
  numeric('volume_last_day', 'Volume in the last 24 hours', 'long'),
  numeric('unique_count', 'Unique objects', 'long'),
  numeric('unique_contribution', 'Unique contribution', 'float'),
  numeric('corroborated_count', 'Corroborated objects', 'long'),
  numeric('corroboration_rate', 'Corroboration rate', 'float'),
  numeric('shared_count', 'Shared objects', 'long'),
  numeric('lead_time_hours', 'Lead time (hours)', 'float'),
  numeric('first_reporter_share', 'First reporter share', 'float'),
  numeric('evaluated_count', 'Evaluated objects', 'long'),
  numeric('revoked_count', 'Revoked objects', 'long'),
  numeric('negative_sightings_count', 'Negative sightings', 'long'),
  numeric('false_positive_count', 'False positives', 'long'),
  numeric('decay_excluded_count', 'Decay exclusions', 'long'),
  numeric('accuracy', 'Accuracy', 'float'),
  numeric('pir_matched_count', 'Objects matching PIRs', 'long'),
  numeric('relevance', 'Relevance', 'float'),
  numeric('sightings_count', 'Sightings', 'long'),
  numeric('security_platform_sightings_count', 'Security platform sightings', 'long'),
  numeric('incidents_count', 'Incidents referencing', 'long'),
  numeric('impact_score', 'Impact score', 'float'),
  numeric('unreferenced_count', 'Never referenced', 'long'),
  numeric('unsighted_count', 'Never sighted', 'long'),
  numeric('expired_count', 'Expired', 'long'),
  numeric('noise_count', 'Noisy objects', 'long'),
  numeric('noise', 'Noise', 'float'),
  numeric('freshness_hours', 'Freshness (hours)', 'float'),
  numeric('median_latency_hours', 'Median publication latency (hours)', 'float'),
  numeric('actionable_count', 'Actionable objects', 'long'),
  numeric('cost_per_actionable_object', 'Cost per actionable object', 'float'),
  numeric('value_score', 'Operational value score', 'float'),
];

const SOURCE_SCORECARD_DEFINITION: ModuleDefinition<any, any> = {
  type: {
    id: 'source-scorecard',
    name: ENTITY_TYPE_SOURCE_SCORECARD,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SOURCE_SCORECARD]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'source_id', label: 'Intelligence source', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_SOURCE], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'source_kind', label: 'Source kind', type: 'string', format: 'enum', values: [...SOURCE_KINDS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    shortText('source_name', 'Source name'),
    { name: 'scorecard_period', label: 'Scorecard period', type: 'string', format: 'enum', values: [...SCORECARD_PERIODS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    date('period_start', 'Period start', true),
    date('period_end', 'Period end', true),
    shortText('scorecard_date', 'Scorecard date', { isFilterable: true }),
    date('computed_at', 'Computed at', true),
    bool('is_live', 'Live scorecard', true),
    date('source_last_asserted_at', 'Last assertion'),
    // Last stream event applied to a live scorecard: replaying a batch never counts it twice
    shortText('live_stream_event_id', 'Last applied stream event'),
    shortText('cost_currency', 'Cost currency'),
    ...SCORECARD_NUMERIC_ATTRIBUTES,
    bool('overlap_complete', 'Complete overlap'),
    {
      name: 'overlap',
      label: 'Overlap',
      type: 'object',
      format: 'standard',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'source_id', label: 'Intelligence source', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'shared_count', label: 'Shared objects', type: 'numeric', precision: 'long', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'share', label: 'Share', type: 'numeric', precision: 'float', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      ],
    },
  ],
  relations: [],
  representative: (stix: any) => `${stix.source_name ?? stix.source_id} - ${stix.scorecard_period}`,
  converter_2_1: (instance: any) => instance,
};
// endregion

// region Collection gap (Enterprise Edition)
const COLLECTION_GAP_DEFINITION: ModuleDefinition<StoreEntityCollectionGap, StixCollectionGap> = {
  type: {
    id: 'collection-gap',
    name: ENTITY_TYPE_COLLECTION_GAP,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // One gap per PIR criterion: the key is a stable hash of the criterion filters
      [ENTITY_TYPE_COLLECTION_GAP]: [{ src: 'pir_id' }, { src: 'criterion_key' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'pir_id', label: 'PIR', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_PIR], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    numeric('criterion_index', 'Criterion index', 'integer'),
    shortText('criterion_key', 'Criterion key', { mandatory: true }),
    json('criterion_filters', 'Criterion filters'),
    numeric('criterion_weight', 'Criterion weight', 'integer'),
    longText('criterion_label', 'Criterion'),
    numeric('gap_coverage_score', 'Gap coverage score', 'integer', true),
    bool('is_gap', 'Is a collection gap', true),
    numeric('matched_relationships', 'Matched relationships', 'long'),
    numeric('recent_relationships', 'Recent relationships', 'long'),
    numeric('distinct_sources', 'Distinct sources', 'integer'),
    {
      name: 'covering_sources',
      label: 'Covering sources',
      type: 'object',
      format: 'standard',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'source_id', label: 'Intelligence source', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'matched_count', label: 'Matched objects', type: 'numeric', precision: 'long', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'share', label: 'Share', type: 'numeric', precision: 'float', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
      ],
    },
    shortText('object_types', 'Object types', { multiple: true, isFilterable: true }),
    shortText('sectors', 'Sectors', { multiple: true, isFilterable: true }),
    shortText('regions', 'Regions', { multiple: true, isFilterable: true }),
    { name: 'recommended_connectors', label: 'Recommended connectors', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'hub_status', label: 'XTM Hub status', type: 'string', format: 'enum', values: [...HUB_CATALOG_STATUSES], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    date('computed_at', 'Computed at', true),
  ],
  relations: [],
  representative: (stix: StixCollectionGap) => stix.name,
  converter_2_1: convertCollectionGapToStix,
};
// endregion

// region Source recommendation (Enterprise Edition)
const SOURCE_RECOMMENDATION_DEFINITION: ModuleDefinition<StoreEntitySourceRecommendation, StixSourceRecommendation> = {
  type: {
    id: 'source-recommendation',
    name: ENTITY_TYPE_SOURCE_RECOMMENDATION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SOURCE_RECOMMENDATION]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'recommendation_kind', label: 'Recommendation kind', type: 'string', format: 'enum', values: [...RECOMMENDATION_KINDS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'recommendation_status', label: 'Recommendation status', type: 'string', format: 'enum', values: [...RECOMMENDATION_STATUSES], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'source_id', label: 'Intelligence source', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_SOURCE], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    shortText('fingerprint', 'Fingerprint', { isFilterable: true, mandatory: true }),
    longText('rationale', 'Rationale'),
    json('payload', 'Recommendation payload'),
    json('recommendation_evidence', 'Recommendation evidence'),
    json('named_authors', 'Named author sources'),
    json('revert_payload', 'Revert payload'),
    longText('apply_result', 'Apply result'),
    longText('error_message', 'Apply error'),
    bool('autonomous', 'Applied by the autonomy policy', true),
    shortText('collection_gap_id', 'Related collection gap'),
    { name: 'pir_id', label: 'PIR', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_PIR], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'applied_by_id', label: 'Applied by', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    date('applied_at', 'Applied at', true),
    { name: 'reverted_by_id', label: 'Reverted by', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    date('reverted_at', 'Reverted at', true),
    { name: 'dismissed_by_id', label: 'Dismissed by', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    date('dismissed_at', 'Dismissed at', true),
    longText('dismiss_reason', 'Dismiss reason'),
    date('proposed_at', 'Proposed at', true),
  ],
  relations: [],
  representative: (stix: StixSourceRecommendation) => stix.name,
  converter_2_1: convertSourceRecommendationToStix,
};
// endregion

registerDefinition(SOURCE_DEFINITION);
registerDefinition(SOURCE_SCORECARD_DEFINITION);
registerDefinition(COLLECTION_GAP_DEFINITION);
registerDefinition(SOURCE_RECOMMENDATION_DEFINITION);
