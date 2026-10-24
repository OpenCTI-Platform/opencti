import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { fullRelationsList, internalFindByIds } from '../../database/middleware-loader';
import { patchAttribute } from '../../database/middleware';
import type { ParsedIntelligenceRequirement, StoreIrPathCondition, StoreIrRule } from './intelligenceRequirement-types';
import { type BasicStoreEntityIntelligenceRequirementMatch, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH } from './intelligenceRequirementMatch-types';
import { parseIrFilters } from './intelligenceRequirement-config';
import { isEntityMatchingFilters, isTypeMatching } from './intelligenceRequirement-engine';

// Relevance engine: score = sum of the points of the matching rules, capped 0-100.
// A required rule that applies but is not met excludes the entity.

export interface IrRuleOutcome {
  rule_id: string;
  name: string;
  points: number;
  hit: boolean;
  reason: string; // '' | 'not applicable' | 'condition not met' | 'required condition not met'
}

export interface IrScoreResult {
  score: number;
  excluded: boolean;
  breakdown: IrRuleOutcome[];
}

const resolveInternalIds = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const entities = await internalFindByIds<BasicStoreEntity>(context, user, ids) as BasicStoreEntity[];
  return Array.from(new Set([...ids, ...entities.map((e) => e.internal_id)]));
};

/**
 * Path condition: the entity is linked by one of relationship_types to an entity
 * that has a target_relationship_type relationship toward one of target_ids.
 * Example: Vulnerability ←exploits— (threat) —targets→ Europe
 */
export const isPathConditionMet = async (context: AuthContext, user: AuthUser, entityId: string, condition: StoreIrPathCondition) => {
  const linked = new Set<string>();
  if (condition.direction === 'incoming' || condition.direction === 'both') {
    const relations = await fullRelationsList<BasicStoreRelation>(context, user, condition.relationship_types, { toId: entityId });
    relations.forEach((r) => linked.add(r.fromId));
  }
  if (condition.direction === 'outgoing' || condition.direction === 'both') {
    const relations = await fullRelationsList<BasicStoreRelation>(context, user, condition.relationship_types, { fromId: entityId });
    relations.forEach((r) => linked.add(r.toId));
  }
  if (linked.size === 0 || condition.target_ids.length === 0) return false;
  const targetIds = await resolveInternalIds(context, user, condition.target_ids);
  const targeting = await fullRelationsList<BasicStoreRelation>(context, user, [condition.target_relationship_type], {
    fromId: Array.from(linked),
    toId: targetIds,
  });
  return targeting.length > 0;
};

const isRuleApplicable = (rule: StoreIrRule, match: BasicStoreEntityIntelligenceRequirementMatch) => {
  if (!isTypeMatching(match.match_entity_type, rule.applies_to_types ?? [])) return false;
  return !rule.applies_to_criterion_id || (match.match_criteria_ids ?? []).includes(rule.applies_to_criterion_id);
};

export const computeMatchScore = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  match: BasicStoreEntityIntelligenceRequirementMatch,
): Promise<IrScoreResult> => {
  const breakdown: IrRuleOutcome[] = [];
  let excluded = false;
  let total = 0;
  const rules = ir.ir_relevance_rules.filter((r) => r.enabled);
  for (let i = 0; i < rules.length; i += 1) {
    const rule = rules[i];
    const outcome: IrRuleOutcome = { rule_id: rule.id, name: rule.name, points: 0, hit: false, reason: '' };
    if (!isRuleApplicable(rule, match)) {
      outcome.reason = 'not applicable';
    } else {
      const filters = parseIrFilters(rule.filters);
      let met = await isEntityMatchingFilters(context, user, match.match_entity_id, filters);
      if (met && rule.path_condition) {
        met = await isPathConditionMet(context, user, match.match_entity_id, rule.path_condition);
      }
      if (met) {
        outcome.hit = true;
        outcome.points = rule.points;
        total += rule.points;
      } else if (rule.required) {
        outcome.reason = 'required condition not met';
        excluded = true;
      } else {
        outcome.reason = 'condition not met';
      }
    }
    breakdown.push(outcome);
  }
  return { score: excluded ? 0 : Math.max(0, Math.min(100, total)), excluded, breakdown };
};

export interface IrRescoreResult {
  match: BasicStoreEntityIntelligenceRequirementMatch;
  previousScore: number;
  result: IrScoreResult;
}

/**
 * Recompute and store the score of a match. Returns the previous score to detect threshold crossings.
 */
export const rescoreMatch = async (
  context: AuthContext,
  user: AuthUser,
  ir: ParsedIntelligenceRequirement,
  match: BasicStoreEntityIntelligenceRequirementMatch,
): Promise<IrRescoreResult> => {
  const previousScore = match.match_excluded ? 0 : (match.match_score ?? 0);
  const result = await computeMatchScore(context, user, ir, match);
  const breakdown = JSON.stringify(result.breakdown);
  if (result.score !== match.match_score || result.excluded !== (match.match_excluded ?? false) || breakdown !== match.match_score_breakdown) {
    await patchAttribute(context, user, match.id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, {
      match_score: result.score,
      match_excluded: result.excluded,
      match_score_breakdown: breakdown,
    });
  }
  return { match, previousScore, result };
};

export const topReasons = (result: IrScoreResult) => result.breakdown
  .filter((o) => o.hit && o.points !== 0)
  .sort((a, b) => Math.abs(b.points) - Math.abs(a.points))
  .slice(0, 3)
  .map((o) => `${o.name} ${o.points > 0 ? '+' : ''}${o.points}`);
