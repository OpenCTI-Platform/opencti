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
}

// A path condition makes one hop in the graph: the entity is linked by one of relationship_types
// to an entity that has a target_relationship_type relationship toward one of target_ids.
// Example: Vulnerability ←exploits— (threat) —targets→ Europe
export interface StoreIrPathCondition {
  relationship_types: string[];
  direction: string;
  target_relationship_type: string;
  target_ids: string[];
}

// A scoring rule: applies to (types, entry criterion) · if (filters and path condition) · then ±points.
// A required rule excludes the entities it applies to when its conditions are not met.
export interface StoreIrRule {
  id: string;
  name: string;
  applies_to_types: string[]; // empty = any type
  applies_to_criterion_id: string | null;
  filters: string | null; // serialized FilterGroup, evaluated on the entity
  path_condition: StoreIrPathCondition | null;
  points: number;
  required: boolean;
  enabled: boolean;
}
// endregion

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
