import * as R from 'ramda';
import { elList, elLoadById, elPaginate } from '../../database/engine';
import { offsetToCursor } from '../../database/utils';
import { patchAttribute } from '../../database/middleware';
import { lockResources } from '../../lock/master-lock';
import { logApp } from '../../config/conf';
import { type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import { now } from '../../utils/format';
import {
  clearFreshnessFlagsOfElements,
  getActiveKnowledgeDecayRules,
  getDecayRuleScope,
  hasSameFreshnessConfiguration,
  KNOWLEDGE_FRESHNESS_INDICES,
  knowledgeDecayRuleLockKey,
  parseKnowledgeDecayFilters,
  resolveKnowledgeDecayRuleTypes,
} from '../decayRule/decayRule-knowledge';
import {
  type BasicStoreEntityDecayRule,
  DEFAULT_FRESHNESS_CONFIDENCE_STEP,
  ENTITY_TYPE_DECAY_RULE,
  FRESHNESS_POLICY_FLAG,
  FRESHNESS_POLICY_LOWER_CONFIDENCE,
  FRESHNESS_POLICY_REVOKE,
} from '../decayRule/decayRule-types';
import { SYSTEM_USER } from '../../utils/access';
import { ATTRIBUTE_FRESHNESS_RULE_ID, ATTRIBUTE_FRESHNESS_STALE, ATTRIBUTE_FRESHNESS_STALE_AT, ATTRIBUTE_LAST_ASSERTED_AT } from './provenance-types';
import { applyProvenanceUpdate, isNoopUpdate } from './provenance-write';
import { listProvenanceTrackedTypes, restrictToTrackedTypes } from './provenance-tracking';

const DAY_IN_MS = 24 * 60 * 60 * 1000;
const FRESHNESS_SCAN_PAGE_SIZE = 500;
// Upper bound of scanned candidates per rule and run, so that shadowed candidates can never stall a run
const FRESHNESS_SCAN_FACTOR = 10;

type FreshnessCandidate = BasicStoreBase & { _index: string; confidence?: number | null; revoked?: boolean | null; last_asserted_at?: string | null };

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

export interface FreshnessState {
  [ATTRIBUTE_FRESHNESS_STALE]?: boolean | null;
  [ATTRIBUTE_FRESHNESS_STALE_AT]?: string | null;
  [ATTRIBUTE_FRESHNESS_RULE_ID]?: string | null;
}

/**
 * Whether the assertions inherited from merged elements make a stale element fresh again: a source asserted it after
 * the stale decision, or within the delay of the active rule that flagged it. A flag whose rule is no longer active
 * is not kept either. Otherwise the flag stays, so that the rule policy is never applied twice.
 */
export const isFreshAfterMerge = (
  target: FreshnessState,
  inheritedLastAssertedAt: string | null | undefined,
  activeRules: Pick<BasicStoreEntityDecayRule, 'id' | 'stale_after_days'>[],
  reference: Date = new Date(),
) => {
  if (target[ATTRIBUTE_FRESHNESS_STALE] !== true || !inheritedLastAssertedAt) {
    return false;
  }
  const staleAt = target[ATTRIBUTE_FRESHNESS_STALE_AT];
  if (staleAt && inheritedLastAssertedAt > staleAt) {
    return true;
  }
  const rule = activeRules.find((candidate) => candidate.id === target[ATTRIBUTE_FRESHNESS_RULE_ID]);
  if (!rule || !Number.isInteger(rule.stale_after_days)) {
    return true;
  }
  return inheritedLastAssertedAt >= computeStaleCutoff(rule.stale_after_days as number, reference);
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
  const flagged = await applyProvenanceUpdate(
    context,
    element,
    { freshnessFlag: { rule_id: rule.id, at, expected_last_asserted_at: element[ATTRIBUTE_LAST_ASSERTED_AT] ?? null } },
    isFlagOnly ? {} : { refresh: true },
  );
  if (isNoopUpdate(flagged)) {
    // Re-asserted since its selection: the element is fresh, no policy applies
    return false;
  }
  result.flagged += 1;
  if (isFlagOnly) {
    return true;
  }
  // Re-assertions write under the lock of the element (upsert, analyst confirmation): holding it from the check to the
  // policy write guarantees that a re-assertion either clears the flag before the check or lands after the write
  const lockIds = R.uniq([element.internal_id, element.standard_id].filter((lockId) => !!lockId));
  let lock: { unlock: () => Promise<void> } | undefined;
  try {
    lock = await lockResources(lockIds);
    const reloaded = await elLoadById<FreshnessCandidate & { freshness_stale?: boolean; freshness_rule_id?: string }>(context, user, element.internal_id, {
      type: element.entity_type,
      baseData: true,
      baseFields: [ATTRIBUTE_FRESHNESS_STALE, ATTRIBUTE_FRESHNESS_RULE_ID, 'confidence', 'revoked'],
    });
    if (reloaded?.freshness_stale !== true || reloaded.freshness_rule_id !== rule.id) {
      result.flagged -= 1;
      return false;
    }
    if (policy === FRESHNESS_POLICY_LOWER_CONFIDENCE) {
      const current = reloaded.confidence ?? 0;
      const lowered = Math.max(0, current - (rule.freshness_confidence_step ?? DEFAULT_FRESHNESS_CONFIDENCE_STEP));
      if (lowered !== current) {
        await patchAttribute(context, user, element.internal_id, element.entity_type, { confidence: lowered }, { locks: lockIds });
        result.lowered += 1;
      }
    }
    if (policy === FRESHNESS_POLICY_REVOKE && reloaded.revoked !== true) {
      await patchAttribute(context, user, element.internal_id, element.entity_type, { revoked: true }, { locks: lockIds });
      result.revoked += 1;
    }
  } catch (err) {
    // The element is evaluated again on the next run
    await applyProvenanceUpdate(context, element, { resetFreshness: true });
    result.flagged -= 1;
    throw err;
  } finally {
    await lock?.unlock();
  }
  return true;
};

/**
 * Apply the policy of a rule under the lock its changes hold (see knowledgeDecayRuleLockKey), with the configuration
 * the run loaded only if the rule still has it. Returns null when the rule changed, was deleted or is being changed:
 * the run stops applying it and the next run loads it again.
 */
const applyFreshnessPolicyOfCurrentRule = async (
  context: AuthContext,
  user: AuthUser,
  rule: BasicStoreEntityDecayRule,
  element: FreshnessCandidate,
  result: KnowledgeFreshnessRunResult,
): Promise<boolean | null> => {
  let lock: { unlock: () => Promise<void> };
  try {
    lock = await lockResources([knowledgeDecayRuleLockKey(rule.id)]);
  } catch (err) {
    logApp.warn('[PROVENANCE] Knowledge decay rule being changed, its policy is applied by the next run', { cause: err, rule_id: rule.id });
    return null;
  }
  try {
    const stored = await elLoadById<BasicStoreEntityDecayRule>(context, SYSTEM_USER, rule.id, { type: ENTITY_TYPE_DECAY_RULE });
    if (!hasSameFreshnessConfiguration(rule, stored)) {
      return null;
    }
    return await applyFreshnessPolicy(context, user, rule, element, result);
  } finally {
    await lock.unlock();
  }
};

export interface RuleScan {
  applied: number;
  scanned: number;
  lastExamined?: BasicStoreBase['sort'];
  // The rule changed since the run loaded it: the scan stopped
  ruleChanged?: boolean;
}

// Where the scan of each rule resumes on the next run (kept in memory: a restart scans from the first candidate)
const scanCursors = new Map<string, string>();

/**
 * Candidates are listed in a stable order. A scan stopped by the budget or by the scan bound resumes after the last
 * candidate it examined, so the candidates a run cannot act on (shadowed by a higher priority rule, failing) never
 * hold back the ones after them; a scan that reached the last candidate starts over from the first one.
 */
export const resumeAfterScan = (scan: RuleScan, budget: number, maxScanned: number) => {
  return scan.applied >= budget || scan.scanned >= maxScanned ? scan.lastExamined : undefined;
};

const scanRuleCandidates = async (
  context: AuthContext,
  user: AuthUser,
  current: PreparedRule,
  filteredHigherRules: PreparedRule[],
  scope: { budget: number; maxScanned: number; after?: string },
  result: KnowledgeFreshnessRunResult,
): Promise<RuleScan> => {
  const { rule } = current;
  const scan: RuleScan = { applied: 0, scanned: 0 };
  await elList<FreshnessCandidate>(context, user, KNOWLEDGE_FRESHNESS_INDICES, {
    types: current.types,
    filters: buildStaleCandidatesFilters(computeStaleCutoff(rule.stale_after_days ?? 0), current.filters),
    baseData: true,
    baseFields: ['confidence', 'revoked', ATTRIBUTE_LAST_ASSERTED_AT],
    first: FRESHNESS_SCAN_PAGE_SIZE,
    maxSize: scope.maxScanned,
    after: scope.after,
    callback: async (candidates) => {
      scan.scanned += candidates.length;
      const shadowed = filteredHigherRules.length > 0
        ? await findIdsMatchingRules(context, user, candidates.map((candidate) => candidate.internal_id), filteredHigherRules)
        : new Set<string>();
      for (let index = 0; index < candidates.length && scan.applied < scope.budget && !scan.ruleChanged; index += 1) {
        const candidate = candidates[index];
        if (!shadowed.has(candidate.internal_id)) {
          try {
            const applied = await applyFreshnessPolicyOfCurrentRule(context, user, rule, candidate, result);
            if (applied === null) {
              scan.ruleChanged = true;
            } else if (applied) {
              scan.applied += 1;
            }
          } catch (err) {
            result.errors += 1;
            logApp.error('[PROVENANCE] Unable to apply the knowledge freshness policy', { cause: err, id: candidate.internal_id, rule_id: rule.id });
          }
        }
        if (!scan.ruleChanged) {
          scan.lastExamined = candidate.sort;
        }
      }
      return scan.applied < scope.budget && !scan.ruleChanged;
    },
  });
  return scan;
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
  const ruleId = current.rule.id;
  const maxScanned = budget * FRESHNESS_SCAN_FACTOR;
  const resumed = scanCursors.get(ruleId);
  const scan = await scanRuleCandidates(context, user, { ...current, types }, filteredHigherRules, { budget, maxScanned, after: resumed }, result);
  let { applied } = scan;
  if (scan.ruleChanged) {
    // The next run scans the rule from its first candidate, with its new configuration
    scanCursors.delete(ruleId);
    return applied;
  }
  let lastExamined = resumeAfterScan(scan, budget, maxScanned);
  if (!lastExamined && resumed) {
    // The last candidate was reached from where the previous run stopped: the rest of the run starts over
    const scope = { budget: budget - applied, maxScanned: maxScanned - scan.scanned };
    const wrapped = await scanRuleCandidates(context, user, { ...current, types }, filteredHigherRules, scope, result);
    applied += wrapped.applied;
    lastExamined = wrapped.ruleChanged ? undefined : resumeAfterScan(wrapped, scope.budget, scope.maxScanned);
  }
  if (lastExamined) {
    scanCursors.set(ruleId, offsetToCursor(lastExamined));
  } else {
    scanCursors.delete(ruleId);
  }
  return applied;
};

// A rule only applies to the types whose provenance is tracked: an untracked type keeps no freshness
const prepareRules = (rules: BasicStoreEntityDecayRule[], trackedTypes: string[]): PreparedRule[] => {
  const prepared: PreparedRule[] = [];
  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index];
    if (!Number.isInteger(rule.stale_after_days) || (rule.stale_after_days as number) < 1) {
      logApp.error('[PROVENANCE] Knowledge decay rule skipped, invalid number of days', { rule_id: rule.id });
      continue;
    }
    try {
      const types = restrictToTrackedTypes(resolveKnowledgeDecayRuleTypes(rule), trackedTypes);
      prepared.push({ rule, types, filters: parseKnowledgeDecayFilters(rule.decay_filters) });
    } catch (err) {
      logApp.error('[PROVENANCE] Knowledge decay rule skipped, invalid configuration', { cause: err, rule_id: rule.id });
    }
  }
  return prepared;
};

const hasLowerPriority = (rule: BasicStoreEntityDecayRule, reference: BasicStoreEntityDecayRule) => {
  return rule.order < reference.order || (rule.order === reference.order && String(rule.created_at).localeCompare(String(reference.created_at)) > 0);
};

/**
 * A rule that gains priority (activated, reordered or retargeted) takes over the elements already flagged by
 * lower priority rules of the same scope: their flags are released so that the next run applies its policy.
 */
export const releaseFlagsTakenOverByRule = async (context: AuthContext, user: AuthUser, rule: BasicStoreEntityDecayRule) => {
  const [current] = rule.active ? prepareRules([rule], await listProvenanceTrackedTypes(context)) : [];
  if (!current || current.types.length === 0) {
    return 0;
  }
  const scope = getDecayRuleScope(rule);
  const activeRules = await getActiveKnowledgeDecayRules(context);
  const lowerRuleIds = activeRules
    .filter((other) => other.id !== rule.id && getDecayRuleScope(other) === scope && hasLowerPriority(other, rule))
    .map((other) => other.id);
  if (lowerRuleIds.length === 0) {
    return 0;
  }
  let released = 0;
  await elList<BasicStoreBase>(context, user, KNOWLEDGE_FRESHNESS_INDICES, {
    types: current.types,
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: [ATTRIBUTE_FRESHNESS_STALE], values: ['true'] },
        { key: [ATTRIBUTE_FRESHNESS_RULE_ID], values: lowerRuleIds },
      ],
      filterGroups: current.filters ? [current.filters] : [],
    },
    baseData: true,
    first: FRESHNESS_SCAN_PAGE_SIZE,
    callback: async (elements) => {
      await clearFreshnessFlagsOfElements(elements.map((element) => element.internal_id));
      released += elements.length;
      return true;
    },
  });
  return released;
};

/**
 * Every rule first gets an equal share of the run, starting at the rule `start`; the rest of the budget then goes, in the
 * same order, to the rules whose scan stopped before their last candidate. A rule with a large backlog therefore never
 * starves the others. With more rules than elements in a run, the first pass ends before the last rule: `nextStart` is
 * the rule after the last one served, where the next run starts, so every rule receives a budget in turn.
 */
export const runWithFairShares = async (
  ruleCount: number,
  batchSize: number,
  apply: (index: number, budget: number) => Promise<number>,
  hasMoreCandidates: (index: number) => boolean,
  start = 0,
): Promise<{ budget: number; nextStart: number }> => {
  let budget = batchSize;
  if (ruleCount === 0 || budget <= 0) {
    return { budget, nextStart: 0 };
  }
  const first = Math.max(0, start) % ruleCount;
  const share = Math.max(1, Math.floor(batchSize / ruleCount));
  let served = 0;
  while (served < ruleCount && budget > 0) {
    budget -= await apply((first + served) % ruleCount, Math.min(share, budget));
    served += 1;
  }
  for (let step = 0; step < ruleCount && budget > 0; step += 1) {
    const index = (first + step) % ruleCount;
    if (hasMoreCandidates(index)) {
      budget -= await apply(index, budget);
    }
  }
  return { budget, nextStart: (first + served) % ruleCount };
};

// First rule of the next run's first pass, so that every active rule is served when they outnumber the batch size
let nextRuleStart = 0;

/**
 * Apply the active knowledge decay rules to at most batchSize elements, each rule acting on the elements that no
 * higher priority rule targets. Re-assertion by any source resets the freshness of an element (see recordUpsertProvenance).
 */
export const applyKnowledgeDecayRules = async (context: AuthContext, user: AuthUser, opts: { batchSize: number }): Promise<KnowledgeFreshnessRunResult> => {
  const result: KnowledgeFreshnessRunResult = { flagged: 0, lowered: 0, revoked: 0, errors: 0 };
  const rules = prepareRules(await getActiveKnowledgeDecayRules(context), await listProvenanceTrackedTypes(context));
  [...scanCursors.keys()].filter((ruleId) => !rules.some(({ rule }) => rule.id === ruleId)).forEach((ruleId) => scanCursors.delete(ruleId));
  const { nextStart } = await runWithFairShares(
    rules.length,
    opts.batchSize,
    (index, budget) => applyKnowledgeDecayRule(context, user, rules[index], rules.slice(0, index), budget, result),
    (index) => scanCursors.has(rules[index].rule.id),
    nextRuleStart,
  );
  nextRuleStart = nextStart;
  return result;
};
