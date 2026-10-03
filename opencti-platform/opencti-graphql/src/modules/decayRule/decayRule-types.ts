import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_DECAY_RULE = 'DecayRule';

// Indicator rules drive the score decay of indicators. Relationship and entity rules are knowledge
// decay rules: they never touch indicator scores, they age knowledge from its last assertion.
export const DECAY_RULE_SCOPE_INDICATOR = 'indicator';
export const DECAY_RULE_SCOPE_RELATIONSHIP = 'relationship';
export const DECAY_RULE_SCOPE_ENTITY = 'entity';
export const DECAY_RULE_SCOPES = [DECAY_RULE_SCOPE_INDICATOR, DECAY_RULE_SCOPE_RELATIONSHIP, DECAY_RULE_SCOPE_ENTITY] as const;
export type DecayRuleScope = typeof DECAY_RULE_SCOPES[number];

export const FRESHNESS_POLICY_FLAG = 'flag';
export const FRESHNESS_POLICY_LOWER_CONFIDENCE = 'lower_confidence';
export const FRESHNESS_POLICY_REVOKE = 'revoke';
export const KNOWLEDGE_FRESHNESS_POLICIES = [FRESHNESS_POLICY_FLAG, FRESHNESS_POLICY_LOWER_CONFIDENCE, FRESHNESS_POLICY_REVOKE] as const;
export type KnowledgeFreshnessPolicyValue = typeof KNOWLEDGE_FRESHNESS_POLICIES[number];

export const DEFAULT_FRESHNESS_CONFIDENCE_STEP = 10;

interface KnowledgeDecayRuleFields {
  target_scope?: DecayRuleScope;
  target_types?: string[];
  freshness_policy?: KnowledgeFreshnessPolicyValue;
  stale_after_days?: number;
  freshness_confidence_step?: number;
}

export interface BasicStoreEntityDecayRule extends BasicStoreEntity, KnowledgeDecayRuleFields {
  name: string;
  built_in: boolean;
  decay_lifetime: number; // in days
  decay_pound: number; // can be changed in other model when feature is ready.
  decay_points: number[]; // reactions points
  decay_revoke_score: number; // revoked when score is <= 20
  decay_filters: string;
  order: number; // low priority = 0
  active: boolean;
}

export interface StoreEntityDecayRule extends StoreEntity, KnowledgeDecayRuleFields {
  name: string;
  built_in: boolean;
  decay_lifetime: number;
  decay_pound: number;
  decay_points: number[];
  decay_revoke_score: number;
  decay_filters: string;
  order: number;
  active: boolean;
}

export interface StixDecayRule extends StixObject {
  name: string;
  description: string;
  decay_lifetime: number;
  decay_pound: number;
  decay_points: number[];
  decay_revoke_score: number;
  decay_filters: string;
  target_scope?: DecayRuleScope;
  target_types?: string[];
  freshness_policy?: KnowledgeFreshnessPolicyValue;
  stale_after_days?: number;
  freshness_confidence_step?: number;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
