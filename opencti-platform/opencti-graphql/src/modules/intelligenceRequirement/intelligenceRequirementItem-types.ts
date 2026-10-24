import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';

// An inbox item of a requirement (output object ③): always one of the same four kinds.
export const ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM = 'IntelligenceRequirementItem';

export const IR_ITEM_KINDS = ['proposed', 'entered', 'score', 'health'];
export const IR_ITEM_STATUSES = ['open', 'done'];
export const IR_ITEM_DECISIONS = ['accept', 'reject', 'acknowledge', 'remove'];

export interface StoreIrItemData {
  criterion_id?: string;
  from_score?: number;
  to_score?: number;
  threshold?: number;
  reasons?: string[];
  message?: string;
}

interface IntelligenceRequirementItemFields {
  ir_id: string;
  item_kind: string;
  item_status: string;
  item_title: string;
  item_entity_id: string | null;
  item_entity_type: string | null;
  item_match_id: string | null;
  item_data: string; // serialized StoreIrItemData
  item_result: string | null;
}

export interface BasicStoreEntityIntelligenceRequirementItem extends BasicStoreEntity, IntelligenceRequirementItemFields {}

export interface StoreEntityIntelligenceRequirementItem extends StoreEntity, IntelligenceRequirementItemFields {}

export interface StixIntelligenceRequirementItem extends StixInternal {
  ir_id: string;
}
