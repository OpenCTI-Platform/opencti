import { elList, elPaginate } from '../../database/engine';
import { patchAttribute } from '../../database/middleware';
import { logApp } from '../../config/conf';
import { type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import { now } from '../../utils/format';
import {
  getActiveKnowledgeDecayRules,
  getDecayRuleScope,
  KNOWLEDGE_FRESHNESS_INDICES,
  parseKnowledgeDecayFilters,
  resolveKnowledgeDecayRuleTypes,
} from '../decayRule/decayRule-knowledge';
import {
  type BasicStoreEntityDecayRule,
  DEFAULT_FRESHNESS_CONFIDENCE_STEP,
  FRESHNESS_POLICY_FLAG,
  FRESHNESS_POLICY_LOWER_CONFIDENCE,
  FRESHNESS_POLICY_REVOKE,
} from '../decayRule/decayRule-types';
import { ATTRIBUTE_FRESHNESS_STALE, ATTRIBUTE_LAST_ASSERTED_AT } from './provenance-types';
import { applyProvenanceUpdate } from './provenance-write';

const DAY_IN_MS = 24 * 60 * 60 * 1000;
const FRESHNESS_SCAN_PAGE_SIZE = 500;
// Upper bound of scanned candidates per rule and run, so that shadowed candidates can never stall a run
const FRESHNESS_SCAN_FACTOR = 10;

type FreshnessCandidate = BasicStoreBase & { _index: string; confidence?: number | null; revoked?: boolean | null };

interface PreparedRule {
  rule: BasicStoreEntityDecayRule;
  types: string[];
  filters: FilterGroup | undefined;
}

export interface KnowledgeFreshnessRunResult {
  flagged: number;
  lowered: number;
  revoked: number;
  errors: number;
}

export const computeStaleCutoff = (staleAfterDays: number, reference: Date = new Date()) => {
  return new Date(reference.getTime() - staleAfterDays * DAY_IN_MS).toISOString();
};

/**
 * A rule only handles the elements that no higher priority rule of the same scope targets.
 * Higher rules without filters are subtracted by type, higher rules with filters are checked per candidate.
 */
export const computeRuleShadowing = (current: PreparedRule, higherRules: PreparedRule[]) => {
  const shadowedTypes = new Set<string>();
  const filteredHigherRules: PreparedRule[] = [];
  for (let index = 0; index < higherRules.length; index += 1) {
    const higher = higherRules[index];
    if (getDecayRuleScope(higher.rule) !== getDecayRuleScope(current.rule)) {
      continue;
    }
    const overlappingTypes = higher.types.filter((type) => current.types.includes(type));
    if (overlappingTypes.length === 0) {
      continue;
    }
    if (higher.filters) {
      filteredHigherRules.push({ ...higher, types: overlappingTypes });
    } else {
      overlappingTypes.forEach((type) => shadowedTypes.add(type));
    }
  }
  return { types: current.types.filter((type) => !shadowedTypes.has(type)), filteredHigherRules };
};

export const buildStaleCandidatesFilters = (cutoff: string, ruleFilters: FilterGroup | undefined): FilterGroup => ({
  mode: FilterMode.And,
  filters: [
    { key: [ATTRIBUTE_LAST_ASSERTED_AT], values: [cutoff], operator: FilterOperator.Lte },
    { key: [ATTRIBUTE_FRESHNESS_STALE], values: ['true'], operator: FilterOperator.NotEq },
    { key: ['revoked'], values: ['true'], operator: FilterOperator.NotEq },
  ],
  filterGroups: ruleFilters ? [ruleFilters] : [],
});

const findIdsMatchingRules = async (context: AuthContext, user: AuthUser, ids: string[], rules: PreparedRule[]) => {
  const matched = new Set<string>();
  for (let index = 0; index < rules.length; index += 1) {
    const { types, filters } = rules[index];
    const hits = await elPaginate<FreshnessCandidate>(context, user, KNOWLEDGE_FRESHNESS_INDICES, {
      types,
      baseData: true,
      first: ids.length,
      connectionFormat: false,
      filters: { mode: FilterMode.And, filters: [{ key: ['internal_id'], values: ids }], filterGroups: filters ? [filters] : [] },
    }) as FreshnessCandidate[];
    hits.forEach((hit) => matched.add(hit.internal_id));
  }
  return matched;
};

/**
 * Flag first (side channel, no stream event), then apply the policy through the regular update path
 * so that confidence changes and revocations get history entries and stream events carrying the flag.
 */
const applyFreshnessPolicy = async (context: AuthContext, user: AuthUser, rule: BasicStoreEntityDecayRule, element: FreshnessCandidate, result: KnowledgeFreshnessRunResult) => {
  const policy = rule.freshness_policy ?? FRESHNESS_POLICY_FLAG;
  const at = now();
  const isFlagOnly = policy === FRESHNESS_POLICY_FLAG;
  // The policy update must load the flagged element: refresh before it, flag only follows the default
  await applyProvenanceUpdate(context, element, { freshnessFlag: { rule_id: rule.id, at } }, isFlagOnly ? {} : { refresh: true });
  result.flagged += 1;
  try {
    if (policy === FRESHNESS_POLICY_LOWER_CONFIDENCE) {
      const current = element.confidence ?? 0;
      const lowered = Math.max(0, current - (rule.freshness_confidence_step ?? DEFAULT_FRESHNESS_CONFIDENCE_STEP));
      if (lowered !== current) {
        await patchAttribute(context, user, element.internal_id, element.entity_type, { confidence: lowered });
        result.lowered += 1;
      }
    }
    if (policy === FRESHNESS_POLICY_REVOKE && element.revoked !== true) {
      await patchAttribute(context, user, element.internal_id, element.entity_type, { revoked: true });
      result.revoked += 1;
    }
  } catch (err) {
    // The element is evaluated again on the next run
    await applyProvenanceUpdate(context, element, { resetFreshness: true });
    result.flagged -= 1;
    throw err;
  }
};

const applyKnowledgeDecayRule = async (
  context: AuthContext,
  user: AuthUser,
  current: PreparedRule,
  higherRules: PreparedRule[],
  budget: number,
  result: KnowledgeFreshnessRunResult,
) => {
  const { types, filteredHigherRules } = computeRuleShadowing(current, higherRules);
  if (types.length === 0 || budget <= 0) {
    return 0;
  }
  const { rule } = current;
  const cutoff = computeStaleCutoff(rule.stale_after_days ?? 0);
  let applied = 0;
  await elList<FreshnessCandidate>(context, user, KNOWLEDGE_FRESHNESS_INDICES, {
    types,
    filters: buildStaleCandidatesFilters(cutoff, current.filters),
    baseData: true,
    baseFields: ['confidence', 'revoked'],
    first: FRESHNESS_SCAN_PAGE_SIZE,
    maxSize: budget * FRESHNESS_SCAN_FACTOR,
    callback: async (candidates) => {
      const shadowed = filteredHigherRules.length > 0
        ? await findIdsMatchingRules(context, user, candidates.map((candidate) => candidate.internal_id), filteredHigherRules)
        : new Set<string>();
      for (let index = 0; index < candidates.length && applied < budget; index += 1) {
        const candidate = candidates[index];
        if (!shadowed.has(candidate.internal_id)) {
          try {
            await applyFreshnessPolicy(context, user, rule, candidate, result);
            applied += 1;
          } catch (err) {
            result.errors += 1;
            logApp.error('[PROVENANCE] Unable to apply the knowledge freshness policy', { cause: err, id: candidate.internal_id, rule_id: rule.id });
          }
        }
      }
      return applied < budget;
    },
  });
  return applied;
};

const prepareRules = (rules: BasicStoreEntityDecayRule[]): PreparedRule[] => {
  const prepared: PreparedRule[] = [];
  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index];
    if (!Number.isInteger(rule.stale_after_days) || (rule.stale_after_days as number) < 1) {
      logApp.error('[PROVENANCE] Knowledge decay rule skipped, invalid number of days', { rule_id: rule.id });
      continue;
    }
    try {
      prepared.push({ rule, types: resolveKnowledgeDecayRuleTypes(rule), filters: parseKnowledgeDecayFilters(rule.decay_filters) });
    } catch (err) {
      logApp.error('[PROVENANCE] Knowledge decay rule skipped, invalid configuration', { cause: err, rule_id: rule.id });
    }
  }
  return prepared;
};

/**
 * Apply the active knowledge decay rules, highest priority first, to at most batchSize elements.
 * Re-assertion by any source resets the freshness of an element (see recordUpsertProvenance).
 */
export const applyKnowledgeDecayRules = async (context: AuthContext, user: AuthUser, opts: { batchSize: number }): Promise<KnowledgeFreshnessRunResult> => {
  const result: KnowledgeFreshnessRunResult = { flagged: 0, lowered: 0, revoked: 0, errors: 0 };
  const rules = prepareRules(await getActiveKnowledgeDecayRules(context));
  let budget = opts.batchSize;
  for (let index = 0; index < rules.length && budget > 0; index += 1) {
    budget -= await applyKnowledgeDecayRule(context, user, rules[index], rules.slice(0, index), budget, result);
  }
  return result;
};
