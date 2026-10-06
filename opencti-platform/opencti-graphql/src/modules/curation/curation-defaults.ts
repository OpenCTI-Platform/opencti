import { CURATION_DETECTORS, type CurationSettings, RELATIONSHIP_CONFLICT_MODE_NOTE } from './curation-types';

export const DEFAULT_CURATED_ENTITY_TYPES = [
  'Intrusion-Set',
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Malware',
  'Tool',
  'Campaign',
  'Attack-Pattern',
  'Infrastructure',
  'Organization',
  'Sector',
];

export const DEFAULT_CURATION_SETTINGS: CurationSettings = {
  curation_enabled: true,
  enabled_detectors: [...CURATION_DETECTORS],
  curated_entity_types: DEFAULT_CURATED_ENTITY_TYPES,
  similarity_threshold: 0.8,
  description_similarity_enabled: false,
  description_similarity_threshold: 0.92,
  behavior_threshold: 0.6,
  proposal_min_confidence: 0.45,
  ambiguous_band_min: 0.55,
  ambiguous_band_max: 0.85,
  adjudication_enabled: false,
  adjudication_agent_slug: null,
  adjudication_run_as_id: null,
  adjudication_daily_limit: 50,
  stale_default_months: 24,
  stale_overrides: [
    { entity_type: 'Infrastructure', months: 12 },
    { entity_type: 'Indicator', months: 12 },
    { entity_type: 'Campaign', months: 36 },
  ],
  relationship_conflict_mode: RELATIONSHIP_CONFLICT_MODE_NOTE,
  merge_record_retention_days: 365,
  digest_enabled: false,
  digest_day: 1,
  digest_recipient_ids: [],
  field_authority_enabled: false,
  field_authority_rules: [],
  scan_max_entities_per_type: 5000,
  force_scan: true,
  last_scan_date: null,
  last_snapshot_date: null,
  last_digest_date: null,
};

export const getDefaultCurationManagerSetting = (): CurationSettings => ({ ...DEFAULT_CURATION_SETTINGS });
