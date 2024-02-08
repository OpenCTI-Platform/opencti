import type { StixDate, StixDomainObject, StixMitreExtension, StixOpenctiExtension } from '../../types/stix-common';
import type { StixKillChainPhase } from '../../types/stix-smo';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { DecayHistory } from '../decayRule/decayRule-domain';

export const INDICATOR_DECAY_FEATURE_FLAG = 'INDICATOR_DECAY';
export const ENTITY_TYPE_INDICATOR = 'Indicator';

// Indicator Specific Properties
export interface StixIndicatorExtension extends StixOpenctiExtension {
  detection: boolean;
  score: number;
  main_observable_type: string;
}
// name, description, indicator_types, pattern, pattern_type, pattern_version, valid_from, valid_until, kill_chain_phases
export interface StixIndicator extends StixDomainObject {
  name: string; // optional
  description: string; // optional
  indicator_types : Array<string>; // optional
  pattern : string;
  pattern_type : string;
  pattern_version : string; // optional
  valid_from : StixDate;
  valid_until : StixDate; // optional
  kill_chain_phases: Array<StixKillChainPhase>; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixIndicatorExtension;
    [STIX_EXT_MITRE] : StixMitreExtension
  };
}

export interface IndicatorDecayRule {
  decay_rule_id: string;
  decay_lifetime: number;
  decay_pound: number;
  decay_points: number[]
  decay_revoke_score: number
}

export interface BasicStoreEntityIndicator extends BasicStoreEntity {
  name: string;
  description: string;
  indicator_types: Array<string>;
  pattern: string;
  pattern_type: string;
  pattern_version: string;
  valid_from: Date;
  valid_until: Date;
  kill_chain_phases: Array<StixKillChainPhase>;
  decay_applied_rule: IndicatorDecayRule;
  decay_history: Array<DecayHistory>;
  decay_base_score: number;
  decay_base_score_date: Date;
}

export interface StoreEntityIndicator extends StoreEntity {
  name: string;
  description: string;
  indicator_types: Array<string>;
  pattern: string;
  pattern_type: string;
  pattern_version: string;
  valid_from: Date;
  valid_until: Date;
  kill_chain_phases: Array<StixKillChainPhase>;
  decay_applied_rule: IndicatorDecayRule;
  decay_history: Array<DecayHistory>;
  decay_base_score: number;
  decay_base_score_date: Date;
}
