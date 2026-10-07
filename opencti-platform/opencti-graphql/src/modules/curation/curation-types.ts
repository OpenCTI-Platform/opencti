import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CURATION_PROPOSAL = 'CurationProposal';
export const ENTITY_TYPE_MERGE_RECORD = 'MergeRecord';
export const ENTITY_TYPE_CURATION_POLICY = 'CurationPolicy';
export const ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT = 'KnowledgeHealthSnapshot';

export const CURATION_MANAGER_ID = 'CURATION_MANAGER';
export const CURATION_ADJUDICATE_INTENT = 'cti.curation_adjudicate';

// region proposals
export const PROPOSAL_KIND_MERGE = 'merge';
export const PROPOSAL_KIND_ALIAS = 'alias';
export const PROPOSAL_KIND_SPLIT = 'split';
export const PROPOSAL_KIND_CONTRADICTION = 'contradiction';
export const PROPOSAL_KIND_STALE = 'stale';
export const PROPOSAL_KIND_RELATIONSHIP_CONFLICT = 'relationship_conflict';
export const PROPOSAL_KIND_TYPE_MISMATCH = 'type_mismatch';
export const PROPOSAL_KIND_FIELD_PRECEDENCE = 'field_precedence';
export const PROPOSAL_KINDS = [
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_SPLIT,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_STALE,
  PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
  PROPOSAL_KIND_TYPE_MISMATCH,
  PROPOSAL_KIND_FIELD_PRECEDENCE,
] as const;
export type ProposalKind = typeof PROPOSAL_KINDS[number];

export const PROPOSAL_STATUS_OPEN = 'open';
export const PROPOSAL_STATUS_ACCEPTED = 'accepted';
export const PROPOSAL_STATUS_REJECTED = 'rejected';
export const PROPOSAL_STATUS_AUTO_APPLIED = 'auto_applied';
export const PROPOSAL_STATUS_REVERTED = 'reverted';
export const PROPOSAL_STATUSES = [
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_ACCEPTED,
  PROPOSAL_STATUS_REJECTED,
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_REVERTED,
] as const;
export type ProposalStatus = typeof PROPOSAL_STATUSES[number];

export const DECISION_ALIAS = 'alias';
export const DECISION_MERGE = 'merge';
export const DECISION_DISTINCT = 'distinct';
export const DECISION_SKIP = 'skip';
export const CURATION_DECISIONS = [DECISION_ALIAS, DECISION_MERGE, DECISION_DISTINCT, DECISION_SKIP] as const;
export type CurationDecision = typeof CURATION_DECISIONS[number];

export const DETECTOR_NORMALIZATION = 'normalization';
export const DETECTOR_SIMILARITY = 'similarity';
export const DETECTOR_BEHAVIOR = 'behavior';
export const DETECTOR_CONTRADICTION = 'contradiction';
export const DETECTOR_STALENESS = 'staleness';
export const DETECTOR_RELATIONSHIP_CONFLICT = 'relationship_conflict';
export const DETECTOR_COMBINED = 'combined';
export const DETECTOR_FIELD_AUTHORITY = 'field_authority';
export const CURATION_DETECTORS = [
  DETECTOR_NORMALIZATION,
  DETECTOR_SIMILARITY,
  DETECTOR_BEHAVIOR,
  DETECTOR_CONTRADICTION,
  DETECTOR_STALENESS,
  DETECTOR_RELATIONSHIP_CONFLICT,
] as const;
export type CurationDetector = typeof CURATION_DETECTORS[number];

export const ACTION_MERGE = 'merge';
export const ACTION_ADD_ALIASES = 'add_aliases';
export const ACTION_UNMERGE = 'unmerge';
export const ACTION_FIX_DATES = 'fix_dates';
export const ACTION_RESOLVE_ATTRIBUTION = 'resolve_attribution';
export const ACTION_UNREVOKE_INDICATOR = 'unrevoke_indicator';
export const ACTION_REVOKE = 'revoke';
export const ACTION_PRESERVE_PROCEDURE = 'preserve_procedure';
export const ACTION_SET_FIELD = 'set_field';
export const ACTION_ACKNOWLEDGE = 'acknowledge';
export const CURATION_ACTIONS = [
  ACTION_MERGE,
  ACTION_ADD_ALIASES,
  ACTION_UNMERGE,
  ACTION_FIX_DATES,
  ACTION_RESOLVE_ATTRIBUTION,
  ACTION_UNREVOKE_INDICATOR,
  ACTION_REVOKE,
  ACTION_PRESERVE_PROCEDURE,
  ACTION_SET_FIELD,
  ACTION_ACKNOWLEDGE,
] as const;
export type CurationAction = typeof CURATION_ACTIONS[number];

export const EVIDENCE_CANONICAL_COLLISION = 'canonical_collision';
export const EVIDENCE_SHARED_ALIAS = 'shared_alias';
export const EVIDENCE_TAXONOMY = 'taxonomy';
export const EVIDENCE_TRIGRAM = 'trigram';
export const EVIDENCE_DESCRIPTION_SIMILARITY = 'description_similarity';
export const EVIDENCE_GRAPH_SIMILARITY = 'graph_similarity';
export const EVIDENCE_ATTACK_OVERLAP = 'attack_overlap';
export const EVIDENCE_SHARED_TOOLS = 'shared_tools';
export const EVIDENCE_SHARED_INFRASTRUCTURE = 'shared_infrastructure';
export const EVIDENCE_VICTIMOLOGY = 'victimology';
export const EVIDENCE_CO_ATTRIBUTION = 'co_attribution';
export const EVIDENCE_SOURCE_AGREEMENT = 'source_agreement';
export const EVIDENCE_DATE_INVERSION = 'date_inversion';
export const EVIDENCE_ATTRIBUTION_CONFLICT = 'attribution_conflict';
export const EVIDENCE_REVOKED_INDICATOR = 'revoked_indicator';
export const EVIDENCE_STALENESS = 'staleness';
export const EVIDENCE_DECAYED_INDICATOR = 'decayed_indicator';
export const EVIDENCE_PROCEDURE_CONFLICT = 'procedure_conflict';
export const EVIDENCE_TYPE_COLLISION = 'type_collision';
export const EVIDENCE_MERGED_ENTITY = 'merged_entity';
export const EVIDENCE_FIELD_CONFLICT = 'field_conflict';

export interface CurationEvidence {
  evidence_type: string;
  score: number;
  weight: number;
  description: string;
  details?: string | null;
}

export interface CurationAdjudication {
  decision: CurationDecision;
  rationale: string;
  agent_slug?: string | null;
  model?: string | null;
  adjudicated_at: string;
  applied: boolean;
  // True only when OpenCTI itself obtained the answer from the agent bound to cti.curation_adjudicate: a decision
  // recorded through the API (curationProposalDecide) is never verified, whatever agent it names.
  verified?: boolean;
}

export interface BasicStoreEntityCurationProposal extends BasicStoreEntity {
  proposal_kind: ProposalKind;
  proposal_status: ProposalStatus;
  proposal_fingerprint: string;
  pair_fingerprints?: string[];
  confidence_score: number;
  in_ambiguous_band: boolean;
  detector: string;
  subject_ids: string[];
  subject_types: string[];
  subject_names: string[];
  target_id?: string | null;
  recommended_action: CurationAction;
  action_payload?: string | null;
  curation_evidence: CurationEvidence[];
  curation_adjudication?: CurationAdjudication | null;
  adjudication_requested_at?: string | null;
  policy_id?: string | null;
  decided_at?: string | null;
  decided_by_id?: string | null;
  decision_rationale?: string | null;
  merge_record_id?: string | null;
  applied_patch?: AppliedPatch | null;
  application_started_at?: string | null;
}

export interface StoreEntityCurationProposal extends StoreEntity, Omit<BasicStoreEntityCurationProposal, keyof BasicStoreEntity> {}

export interface StixCurationProposal extends StixObject {
  name: string;
  proposal_kind: string;
  proposal_status: string;
  confidence_score: number;
  subject_ids: string[];
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region applied patches (reverse operations of non-merge applies)
export interface AppliedPatchOperation {
  element_id: string;
  entity_type: string;
  key: string;
  previous: unknown;
  value: unknown;
}
export interface AppliedPatch {
  operations: AppliedPatchOperation[];
  created_ids?: string[];
  // The version (`updated_at`) of each element the apply created: the revert deletes only an element still at that version.
  created_versions?: Record<string, string>;
  deleted_ids?: string[];
  // The delete operation each deletion created, by deleted id: the revert restores that one and never a later one.
  delete_operation_ids?: Record<string, string>;
  applied_at: string;
}
// endregion

// region merge records
// Pending: the record is written before the merge mutates the graph, and becomes active once the merge succeeded.
export const MERGE_STATUS_PENDING = 'pending';
export const MERGE_STATUS_ACTIVE = 'active';
export const MERGE_STATUS_REVERTED = 'reverted';
export const MERGE_STATUS_PARTIALLY_REVERTED = 'partially_reverted';
export const MERGE_STATUS_IRREVERSIBLE = 'irreversible';
export const MERGE_STATUSES = [
  MERGE_STATUS_PENDING,
  MERGE_STATUS_ACTIVE,
  MERGE_STATUS_REVERTED,
  MERGE_STATUS_PARTIALLY_REVERTED,
  MERGE_STATUS_IRREVERSIBLE,
] as const;
export type MergeStatus = typeof MERGE_STATUSES[number];
// Why a merge cannot be undone, recorded as a stable code that clients translate.
export const IRREVERSIBLE_TOO_MANY_REMOVED_RELATIONSHIPS = 'too_many_removed_relationships';
export const IRREVERSIBLE_TOO_MANY_MOVED_RELATIONSHIPS = 'too_many_moved_relationships';
export const IRREVERSIBLE_FILE_NAME_COLLISION = 'file_name_collision';
export const IRREVERSIBLE_FILE_NOT_MOVED = 'file_not_moved';
export const IRREVERSIBLE_MERGE_INTERRUPTED = 'merge_interrupted';
export const IRREVERSIBLE_MERGE_RERUN = 'merge_rerun_after_interruption';
export const IRREVERSIBLE_MERGED_ENTITY_DELETED = 'merged_entity_deleted';
export const IRREVERSIBLE_RETENTION_OVER = 'retention_over';

export interface MergeSnapshotRef {
  [inputName: string]: string | string[] | null;
}

export interface MergeRedirectedRelationship {
  id: string;
  entity_type: string;
  side: 'from' | 'to';
  other_id: string;
  other_type: string;
}

export interface MergeRecreatableRelationship {
  id: string;
  standard_id: string;
  entity_type: string;
  from_id: string;
  from_type: string;
  to_id: string;
  to_type: string;
  attributes: Record<string, unknown>;
  refs: MergeSnapshotRef;
}

export interface MergeSourceSnapshot {
  internal_id: string;
  standard_id: string;
  entity_type: string;
  name: string;
  attributes: Record<string, unknown>;
  refs: MergeSnapshotRef;
  redirected: MergeRedirectedRelationship[];
  recreatable: MergeRecreatableRelationship[];
  moved_file_ids: string[];
  contributed_aliases: string[];
  contributed_stix_ids: string[];
  reverted_at?: string | null;
}

export interface MergeTargetSnapshot {
  internal_id: string;
  standard_id: string;
  entity_type: string;
  name: string;
  attributes: Record<string, unknown>;
  refs: MergeSnapshotRef;
  // State right after the merge: the difference with the pre-merge state is what the merge changed.
  post_attributes: Record<string, unknown>;
  post_refs: MergeSnapshotRef;
  taken_from_source_id: string | null;
}

export interface MergeSnapshot {
  target: MergeTargetSnapshot;
  sources: MergeSourceSnapshot[];
}

export interface AliasProvenance {
  alias: string;
  source_id: string;
  source_aliases: string[];
  relationship_ids: string[];
}

export interface BasicStoreEntityMergeRecord extends BasicStoreEntity {
  merge_target_id: string;
  merge_target_type: string;
  merge_target_name: string;
  merge_source_ids: string[];
  merge_source_names: string[];
  merge_status: MergeStatus;
  merge_snapshot: MergeSnapshot;
  alias_provenance: AliasProvenance[];
  reversible_until: string;
  irreversible_reason?: string | null;
  merge_started_at?: string | null;
  relationships_redirected_count: number;
  relationships_recreatable_count: number;
  merged_by_id: string;
  proposal_id?: string | null;
  unmerged_at?: string | null;
  unmerged_by_id?: string | null;
  // Sources of an unmerge that started but did not complete: the next unmerge resumes exactly them.
  unmerge_pending_source_ids?: string[] | null;
}

export interface StoreEntityMergeRecord extends StoreEntity, Omit<BasicStoreEntityMergeRecord, keyof BasicStoreEntity> {}

export interface StixMergeRecord extends StixObject {
  name: string;
  merge_target_id: string;
  merge_source_ids: string[];
  merge_status: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region policies
export const SOURCE_CLASS_ANY = 'any';
export const SOURCE_CLASS_CONNECTOR = 'connector';
export const SOURCE_CLASS_MANUAL = 'manual';
export const POLICY_SOURCE_CLASSES = [SOURCE_CLASS_ANY, SOURCE_CLASS_CONNECTOR, SOURCE_CLASS_MANUAL] as const;
export type PolicySourceClass = typeof POLICY_SOURCE_CLASSES[number];

export interface CurationPolicyDryRunResult {
  computed_at: string;
  eligible_count: number;
  excluded_count: number;
  estimated_impact: { key: string; count: number }[];
  exclusions: { key: string; count: number }[];
  sample_proposal_ids: string[];
  // The user the dry run counted for: it only counts the proposals this user can read.
  computed_by_id?: string;
}

export interface BasicStoreEntityCurationPolicy extends BasicStoreEntity {
  name: string;
  description: string;
  policy_enabled: boolean;
  policy_entity_types: string[];
  policy_kinds: ProposalKind[];
  policy_source_class: PolicySourceClass;
  auto_apply_threshold: number;
  forbid_open_contradiction: boolean;
  require_adjudication: boolean;
  max_applies_per_run: number;
  last_applied_at?: string | null;
  last_dry_run?: CurationPolicyDryRunResult | null;
  applied_count: number;
}

export interface StoreEntityCurationPolicy extends StoreEntity, Omit<BasicStoreEntityCurationPolicy, keyof BasicStoreEntity> {}

export interface StixCurationPolicy extends StixObject {
  name: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region knowledge health
export interface KnowledgeHealthComponent {
  component: string;
  value: number;
  weight: number;
  score: number;
}

export interface KnowledgeHealthMetrics {
  curated_entities_count: number;
  duplicate_estimate: number;
  duplicate_rate: number;
  contradiction_count: number;
  stale_count: number;
  stale_share: number;
  alias_coverage: number;
  source_conflict_rate: number;
  open_proposals_count: number;
  auto_applied_count: number;
  accepted_count: number;
  rejected_count: number;
  reverted_count: number;
  merges_count: number;
  unmerges_count: number;
}

export const KNOWLEDGE_HEALTH_METRIC_KEYS: Array<keyof KnowledgeHealthMetrics> = [
  'curated_entities_count',
  'duplicate_estimate',
  'duplicate_rate',
  'contradiction_count',
  'stale_count',
  'stale_share',
  'alias_coverage',
  'source_conflict_rate',
  'open_proposals_count',
  'auto_applied_count',
  'accepted_count',
  'rejected_count',
  'reverted_count',
  'merges_count',
  'unmerges_count',
];

export interface BasicStoreEntityKnowledgeHealthSnapshot extends BasicStoreEntity {
  snapshot_date: string;
  health_score: number;
  score_trend?: number | null;
  // Read and shown, never filtered, sorted or aggregated on: stored as one non-indexed object.
  health_metrics: KnowledgeHealthMetrics;
  score_breakdown: KnowledgeHealthComponent[];
  digest_sent_at?: string | null;
}

export interface StoreEntityKnowledgeHealthSnapshot extends StoreEntity, Omit<BasicStoreEntityKnowledgeHealthSnapshot, keyof BasicStoreEntity> {}

export interface StixKnowledgeHealthSnapshot extends StixObject {
  snapshot_date: string;
  health_score: number;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region settings
export const RELATIONSHIP_CONFLICT_MODE_NOTE = 'note';
export const RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY = 'detect_only';
export const RELATIONSHIP_CONFLICT_MODES = [RELATIONSHIP_CONFLICT_MODE_NOTE, RELATIONSHIP_CONFLICT_MODE_DETECT_ONLY] as const;
export type RelationshipConflictMode = typeof RELATIONSHIP_CONFLICT_MODES[number];

export const AUTHORITY_SOURCE_AUTHOR = 'author';
export const AUTHORITY_SOURCE_CONNECTOR = 'connector';
export type AuthoritySourceType = typeof AUTHORITY_SOURCE_AUTHOR | typeof AUTHORITY_SOURCE_CONNECTOR;

export interface FieldAuthoritySource {
  source_type: AuthoritySourceType;
  source_id: string;
}

export interface FieldAuthorityRule {
  entity_type: string;
  attribute: string;
  sources: FieldAuthoritySource[]; // ordered, first = most authoritative
}

export interface StalenessOverride {
  entity_type: string;
  months: number;
}

export interface CurationSettings {
  curation_enabled: boolean;
  enabled_detectors: CurationDetector[];
  curated_entity_types: string[];
  similarity_threshold: number;
  description_similarity_enabled: boolean;
  description_similarity_threshold: number;
  behavior_threshold: number;
  proposal_min_confidence: number;
  ambiguous_band_min: number;
  ambiguous_band_max: number;
  adjudication_enabled: boolean;
  adjudication_agent_slug: string | null;
  adjudication_run_as_id: string | null;
  adjudication_daily_limit: number;
  stale_default_months: number;
  stale_overrides: StalenessOverride[];
  relationship_conflict_mode: RelationshipConflictMode;
  merge_record_retention_days: number;
  digest_enabled: boolean;
  digest_day: number;
  digest_recipient_ids: string[];
  field_authority_enabled: boolean;
  field_authority_rules: FieldAuthorityRule[];
  scan_max_entities_per_type: number;
  force_scan: boolean;
  last_scan_date: string | null;
  last_snapshot_date: string | null;
  last_digest_date: string | null;
}
// endregion

// region detector candidates (pure inputs for evidence computation)
export interface CurationCandidateEntity {
  internal_id: string;
  standard_id: string;
  entity_type: string;
  name: string;
  aliases: string[];
  description?: string | null;
  created_by_id?: string | null;
  creator_ids?: string[];
  marking_ids: string[];
  organization_ids: string[];
  updated_at?: string | null;
  x_opencti_graph_metrics?: Record<string, unknown> | null;
}

export interface ProposalDraft {
  kind: ProposalKind;
  detector: string;
  subjects: Array<{ id: string; entity_type: string; name: string }>;
  target_id?: string | null;
  recommended_action: CurationAction;
  action_payload?: Record<string, unknown> | null;
  evidence: CurationEvidence[];
  confidence: number;
}
// endregion
