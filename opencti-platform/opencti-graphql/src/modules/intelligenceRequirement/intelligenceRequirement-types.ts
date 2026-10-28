import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';

// Proof of concept of a generic PIR model, next to the existing Pir module (which is left untouched).
// A requirement is made of four blocks:
// - Question: the question and its key intelligence questions (KIQ)
// - Subjects: named groups of anchors (a list of entities, a dynamic filter or keywords)
// - Scope: entry criteria (what makes an entity enter the requirement)
// - Relevance: scoring rules (how important an entity of the requirement is)

export const ENTITY_TYPE_INTELLIGENCE_REQUIREMENT = 'IntelligenceRequirement';

export const IR_PRIORITIES = ['critical', 'high', 'medium', 'low'];
export const IR_STATUSES = ['active', 'paused'];
export const IR_BRIEF_FREQUENCIES = ['off', 'daily', 'weekly'];
export const IR_SUBJECT_GROUP_KINDS = ['list', 'filter', 'keywords'];
export const IR_SUBJECT_GROUP_ROLES = ['entry', 'context', 'both'];
export const IR_CRITERION_KINDS = ['graph', 'attribute', 'keywords'];
export const IR_CRITERION_MODES = ['auto', 'propose', 'off'];
export const IR_DIRECTIONS = ['outgoing', 'incoming', 'both'];
export const IR_KEYWORD_FIELDS = ['name', 'description', 'content'];

// region configuration blocks
export interface StoreIrKiq {
  id: string;
  text: string;
  criteria_ids: string[];
}

export interface StoreIrSubjectGroup {
  id: string;
  name: string;
  kind: string; // list | filter | keywords
  role: string; // entry | context | both
  entity_ids: string[]; // kind = list
  filters: string | null; // kind = filter, serialized FilterGroup
  keywords: string[]; // kind = keywords
  exclude_keywords?: string[]; // kind = keywords: phrases removed from the texts before the search (e.g. "targets russia")
}

// A link to subject groups: the entity has one of relationship_types with a member of one of the groups (either direction).
// The relationship type "object" reads the content of a container: the entity contains a member of the groups.
// Example: (intrusion set) —targets→ a member of [European regions]; (report) contains a member of [European regions].
export interface StoreIrGroupLink {
  relationship_types: string[];
  group_ids: string[]; // list or filter subject groups (a filter group is re-evaluated: e.g. every ransomware malware)
}

// A scope condition of a criterion: an entity that takes the path of the criterion only enters the requirement
// when every condition that applies to its type is met (filters and path condition, evaluated on the entity).
// Example: (intrusion set) —targets→ Healthcare, and —targets→ a country located in Europe, and last seen in the last 12 months.
export interface StoreIrCondition {
  id: string;
  name: string;
  applies_to_types: string[]; // empty = every type the criterion brings
  filters: string | null; // serialized FilterGroup, evaluated on the entity
  link?: StoreIrGroupLink | null;
  path_condition: StoreIrPathCondition | null;
}

// One single format for every entry criterion:
// - graph: (entities of from_group_ids or already in the requirement, of from_types) —relationship_types→ (target_types + target_filters)
//   The relationship type "object" reads the content of containers: (report) —object→ (contained entity).
// - attribute: (target_types + target_filters), zero hop, on entity events
// - keywords: (keywords of from_group_ids) found in keyword_fields of an entity or a container (its contained objects are proposed)
export interface StoreIrCriterion {
  id: string;
  name: string;
  kind: string; // graph | attribute | keywords
  from_group_ids: string[];
  from_in_requirement: boolean; // second hop: start from the entities already in the requirement
  from_types?: string[]; // only start from entities of these types (empty: any type)
  relationship_types: string[];
  direction: string; // outgoing | incoming | both
  target_types: string[];
  target_filters: string | null; // serialized FilterGroup
  keyword_fields: string[];
  mode: string; // auto | propose | off
  conditions?: StoreIrCondition[]; // all must be met (AND) for the entity to be eligible
}

// A path condition makes one hop in the graph: the entity is linked by one of relationship_types
// to an entity that has a target_relationship_type relationship toward one of target_ids.
// Example: Vulnerability ←exploits— (threat) —targets→ Europe
export interface StoreIrPathCondition {
  relationship_types: string[];
  direction: string;
  target_relationship_type: string;
  target_ids: string[];
  target_group_ids?: string[]; // the members of these subject groups are targets too
}

// A scoring rule: applies to (types, entry criterion) · if (filters and path condition) · then ±points.
// Rules only rank the entities of the requirement: what may enter is decided by the conditions of the criteria.
// Legacy "required" rules are converted into scope conditions when a configuration is read or saved.
export interface StoreIrRule {
  id: string;
  name: string;
  applies_to_types: string[]; // empty = any type
  applies_to_criterion_id: string | null;
  filters: string | null; // serialized FilterGroup, evaluated on the entity
  link?: StoreIrGroupLink | null;
  path_condition: StoreIrPathCondition | null;
  points: number;
  required: boolean; // legacy: always false once converted into scope conditions
  enabled: boolean;
}
// endregion

// What the engine did for a requirement: where its catch-up started, its last batch, its totals and its last error
export interface StoreIrBatchStats {
  events: number;
  entered: number;
  updated: number;
  rescored: number;
  backfilled: number;
  skipped?: number; // candidates that did not meet the conditions of the scope: evaluated, not stored
  errors: number;
}
export interface StoreIrProcessing {
  catchup_from?: string; // stream event id where the catch-up started (creation minus the rescan window)
  last_batch?: StoreIrBatchStats & { at: string; duration_ms: number };
  totals?: StoreIrBatchStats;
  last_error?: { at: string; message: string; event_id?: string };
}

interface IntelligenceRequirementFields {
  name: string;
  description: string;
  ir_question: string;
  ir_priority: string;
  ir_status: string;
  ir_kiqs: string; // serialized StoreIrKiq[]
  ir_subject_groups: string; // serialized StoreIrSubjectGroup[]
  ir_scope_criteria: string; // serialized StoreIrCriterion[]
  ir_relevance_rules: string; // serialized StoreIrRule[]
  ir_thresholds: number[];
  ir_rescan_days: number;
  ir_brief_frequency?: string; // off | daily | weekly: AI brief delivered to the inbox
  ir_last_brief_at?: Date | string | null;
  ir_processing?: string; // serialized StoreIrProcessing, written by the engine with lastEventId
  lastEventId: string;
}

export interface BasicStoreEntityIntelligenceRequirement extends BasicStoreEntity, IntelligenceRequirementFields {}

export interface StoreEntityIntelligenceRequirement extends StoreEntity, IntelligenceRequirementFields {}

export interface StixIntelligenceRequirement extends StixInternal {
  name: string;
}

export interface ParsedIntelligenceRequirement extends Omit<BasicStoreEntityIntelligenceRequirement, 'ir_kiqs' | 'ir_subject_groups' | 'ir_scope_criteria' | 'ir_relevance_rules'> {
  ir_kiqs: StoreIrKiq[];
  ir_subject_groups: StoreIrSubjectGroup[];
  ir_scope_criteria: StoreIrCriterion[];
  ir_relevance_rules: StoreIrRule[];
}
