import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../../types/store';

export const ENTITY_TYPE_DEFENSE_GAP = 'DefenseGap';

export const DEFENSE_GAP_STATUS_OPEN = 'open';
export const DEFENSE_GAP_STATUS_CLOSED = 'closed';

export interface DefenseGapValidationRequest {
  security_coverage_id: string;
  grouping_id: string;
  threat_id?: string;
  requested_at: string;
  requested_by: string;
}

// System-wide record of a (technique, platform) pair. The reader-facing values (level, layers, priority)
// are always re-evaluated with the reader's access; this record keeps the lifecycle and the validation tracking.
interface DefenseGapFields {
  name: string;
  attack_pattern_id: string;
  platform_id: string;
  level: number;
  recommended_action: string;
  status: string;
  opened_at: string;
  closed_at?: string;
  computed_at: string;
  validation_requests?: DefenseGapValidationRequest[];
  last_validation_requested_at?: string;
}

export interface BasicStoreEntityDefenseGap extends BasicStoreEntity, DefenseGapFields {}

export interface StoreEntityDefenseGap extends StoreEntity, DefenseGapFields {}

export interface StixDefenseGap extends StixObject {
  name: string;
  attack_pattern_id: string;
  platform_id: string;
  level: number;
  recommended_action: string;
  status: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
