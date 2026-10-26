import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';

// An entity of a requirement: the output object ① of the requirement (entity · entry criterion · proof · status · score).
export const ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH = 'IntelligenceRequirementMatch';

export const IR_MATCH_STATUSES = ['auto', 'proposed', 'accepted', 'rejected', 'removed'];
// Statuses for which the entity is part of the requirement
export const IR_MATCH_IN_STATUSES = ['auto', 'accepted'];

// Why an entity entered: one entry per (criterion, proof)
export interface StoreIrMatchExplanation {
  criterion_id: string;
  kind: string; // graph | attribute | keywords
  at: string;
  // graph
  anchor_id?: string;
  anchor_type?: string;
  relationship_id?: string;
  relationship_type?: string;
  direction?: string; // outgoing | incoming, seen from the anchor
  // keywords
  keyword?: string;
  field?: string;
  container_id?: string;
  container_type?: string;
}

interface IntelligenceRequirementMatchFields {
  ir_id: string;
  match_entity_id: string;
  match_entity_type: string;
  match_entity_name?: string; // copied from the entity: search and sort by name
  match_status: string;
  match_criteria_ids: string[];
  match_explanations: string; // serialized StoreIrMatchExplanation[]
  match_score: number;
  match_score_breakdown: string; // serialized, computed by the relevance engine
  match_excluded: boolean;
  match_last_fact_at: Date;
}

export interface BasicStoreEntityIntelligenceRequirementMatch extends BasicStoreEntity, IntelligenceRequirementMatchFields {}

export interface StoreEntityIntelligenceRequirementMatch extends StoreEntity, IntelligenceRequirementMatchFields {}

export interface StixIntelligenceRequirementMatch extends StixInternal {
  ir_id: string;
  match_entity_id: string;
}
