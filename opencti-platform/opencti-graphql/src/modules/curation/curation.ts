import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { objectMarking, objectOrganization } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import {
  CURATION_ACTIONS,
  ENTITY_TYPE_CURATION_POLICY,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT,
  ENTITY_TYPE_MERGE_RECORD,
  MERGE_STATUSES,
  POLICY_SOURCE_CLASSES,
  PROPOSAL_KINDS,
  PROPOSAL_STATUSES,
  type StixCurationPolicy,
  type StixCurationProposal,
  type StixKnowledgeHealthSnapshot,
  type StixMergeRecord,
  type StoreEntityCurationPolicy,
  type StoreEntityCurationProposal,
  type StoreEntityKnowledgeHealthSnapshot,
  type StoreEntityMergeRecord,
} from './curation-types';
import { convertCurationPolicyToStix, convertCurationProposalToStix, convertKnowledgeHealthSnapshotToStix, convertMergeRecordToStix } from './curation-converter';

const CURATION_PROPOSAL_DEFINITION: ModuleDefinition<StoreEntityCurationProposal, StixCurationProposal> = {
  type: {
    id: 'curationProposals',
    name: ENTITY_TYPE_CURATION_PROPOSAL,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CURATION_PROPOSAL]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'proposal_kind', label: 'Proposal kind', type: 'string', format: 'enum', values: [...PROPOSAL_KINDS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'proposal_status', label: 'Proposal status', type: 'string', format: 'enum', values: [...PROPOSAL_STATUSES], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'proposal_fingerprint', label: 'Proposal fingerprint', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pair_fingerprints', label: 'Pair fingerprints', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'confidence_score', label: 'Curation confidence', type: 'numeric', precision: 'float', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'in_ambiguous_band', label: 'In ambiguous band', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'detector', label: 'Detector', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'subject_ids',
      label: 'Subjects',
      type: 'string',
      format: 'id',
      entityTypes: [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true,
    },
    { name: 'subject_types', label: 'Subject types', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'subject_names', label: 'Subject names', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'target_id', label: 'Suggested target', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'recommended_action', label: 'Recommended action', type: 'string', format: 'enum', values: [...CURATION_ACTIONS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'action_payload', label: 'Action payload', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'curation_evidence', label: 'Curation evidence', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'curation_adjudication', label: 'Adjudication', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'adjudication_requested_at', label: 'Adjudication requested at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'policy_id', label: 'Policy', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'decided_at', label: 'Decision date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'decided_by_id',
      label: 'Decided by',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    { name: 'decision_rationale', label: 'Decision rationale', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'merge_record_id', label: 'Merge record', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'applied_patch', label: 'Applied patch', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'application_started_at', label: 'Application started at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  relationsRefs: [
    { ...objectMarking, isFilterable: false },
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixCurationProposal) => stix.name,
  converter_2_1: convertCurationProposalToStix,
};

const MERGE_RECORD_DEFINITION: ModuleDefinition<StoreEntityMergeRecord, StixMergeRecord> = {
  type: {
    id: 'mergeRecords',
    name: ENTITY_TYPE_MERGE_RECORD,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_MERGE_RECORD]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'merge_target_id',
      label: 'Merge target',
      type: 'string',
      format: 'id',
      entityTypes: [ABSTRACT_STIX_CORE_OBJECT],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    { name: 'merge_target_type', label: 'Merged entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'merge_target_name', label: 'Merged entity name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'merge_source_ids', label: 'Merged sources', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'merge_source_names', label: 'Merged source names', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'merge_status', label: 'Merge status', type: 'string', format: 'enum', values: [...MERGE_STATUSES], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'merge_snapshot', label: 'Merge snapshot', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'alias_provenance', label: 'Alias provenance', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'reversible_until', label: 'Reversible until', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'irreversible_reason', label: 'Irreversible reason', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'merge_started_at', label: 'Merge started at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'relationships_redirected_count', label: 'Relationships redirected', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'relationships_recreatable_count', label: 'Relationships recreatable', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    {
      name: 'merged_by_id',
      label: 'Merged by',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    { name: 'proposal_id', label: 'Curation proposal', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'unmerged_at', label: 'Unmerge date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'unmerged_by_id',
      label: 'Unmerged by',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    { name: 'unmerge_pending_source_ids', label: 'Unmerge in progress', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  ],
  relations: [],
  relationsRefs: [
    { ...objectMarking, isFilterable: false },
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixMergeRecord) => stix.name,
  converter_2_1: convertMergeRecordToStix,
};

const CURATION_POLICY_DEFINITION: ModuleDefinition<StoreEntityCurationPolicy, StixCurationPolicy> = {
  type: {
    id: 'curationPolicies',
    name: ENTITY_TYPE_CURATION_POLICY,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CURATION_POLICY]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'policy_enabled', label: 'Policy enabled', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'policy_entity_types', label: 'Policy entity types', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'policy_kinds', label: 'Proposal kinds', type: 'string', format: 'enum', values: [...PROPOSAL_KINDS], mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'policy_source_class', label: 'Source class', type: 'string', format: 'enum', values: [...POLICY_SOURCE_CLASSES], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'auto_apply_threshold', label: 'Auto-apply threshold', type: 'numeric', precision: 'float', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'forbid_open_contradiction', label: 'Never apply with open contradictions', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'require_adjudication', label: 'Require adjudication agreement', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'max_applies_per_run', label: 'Maximum applies per run', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'last_applied_at', label: 'Last applied', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'last_dry_run', label: 'Last dry run', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'applied_count', label: 'Applied proposals', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixCurationPolicy) => stix.name,
  converter_2_1: convertCurationPolicyToStix,
};

const healthNumeric = (name: string, label: string, precision: 'integer' | 'float') => ({
  name, label, type: 'numeric' as const, precision, mandatoryType: 'internal' as const, editDefault: false, multiple: false, upsert: false, isFilterable: false,
});

const KNOWLEDGE_HEALTH_SNAPSHOT_DEFINITION: ModuleDefinition<StoreEntityKnowledgeHealthSnapshot, StixKnowledgeHealthSnapshot> = {
  type: {
    id: 'knowledgeHealthSnapshots',
    name: ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_KNOWLEDGE_HEALTH_SNAPSHOT]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'snapshot_date', label: 'Snapshot date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    healthNumeric('health_score', 'Health score', 'integer'),
    healthNumeric('score_trend', 'Score trend', 'float'),
    { name: 'health_metrics', label: 'Health metrics', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'score_breakdown', label: 'Score breakdown', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'digest_sent_at', label: 'Digest sent at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixKnowledgeHealthSnapshot) => stix.snapshot_date,
  converter_2_1: convertKnowledgeHealthSnapshotToStix,
};

registerDefinition(CURATION_PROPOSAL_DEFINITION);
registerDefinition(MERGE_RECORD_DEFINITION);
registerDefinition(CURATION_POLICY_DEFINITION);
registerDefinition(KNOWLEDGE_HEALTH_SNAPSHOT_DEFINITION);
