import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import {
  BUILT_IN_KNOWLEDGE_DECAY_RULES,
  checkDecayRulePatch,
  getDecayRuleScope,
  hasSameFreshnessConfiguration,
  isKnowledgeDecayRule,
  type KnowledgeDecayRuleDefinition,
  resolveKnowledgeDecayRuleTypes,
  validateKnowledgeDecayRule,
} from '../../../../src/modules/decayRule/decayRule-knowledge';
import type { BasicStoreEntityDecayRule } from '../../../../src/modules/decayRule/decayRule-types';
import { STIX_CORE_RELATIONSHIPS } from '../../../../src/schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import {
  buildStaleCandidatesFilters,
  computeRuleShadowing,
  computeStaleCutoff,
  isFreshAfterMerge,
  resumeAfterScan,
  runWithFairShares,
} from '../../../../src/modules/provenance/provenance-freshness';

const relationshipRule = (overrides: Partial<KnowledgeDecayRuleDefinition> = {}): KnowledgeDecayRuleDefinition => ({
  name: 'Stale C2',
  order: 1,
  active: true,
  target_scope: 'relationship',
  target_types: ['communicates-with'],
  freshness_policy: 'flag',
  stale_after_days: 180,
  ...overrides,
});

const storedRule = (overrides: Partial<BasicStoreEntityDecayRule> = {}) => ({
  id: 'rule-1',
  internal_id: 'rule-1',
  name: 'Rule',
  built_in: false,
  order: 1,
  active: true,
  target_scope: 'relationship',
  target_types: ['uses'],
  freshness_policy: 'flag',
  stale_after_days: 365,
  ...overrides,
}) as unknown as BasicStoreEntityDecayRule;

describe('Knowledge decay rules', () => {
  it('should default the scope of legacy rules to indicators', () => {
    expect(getDecayRuleScope({})).toEqual('indicator');
    expect(isKnowledgeDecayRule({ target_scope: 'indicator' })).toEqual(false);
    expect(isKnowledgeDecayRule({ target_scope: 'relationship' })).toEqual(true);
    expect(isKnowledgeDecayRule({ target_scope: 'entity' })).toEqual(true);
  });

  it('should resolve concrete target types', () => {
    expect(resolveKnowledgeDecayRuleTypes({ target_scope: 'relationship', target_types: [] })).toEqual([...STIX_CORE_RELATIONSHIPS, STIX_SIGHTING_RELATIONSHIP]);
    expect(resolveKnowledgeDecayRuleTypes({ target_scope: 'relationship', target_types: ['uses'] })).toEqual(['uses']);
    expect(resolveKnowledgeDecayRuleTypes({ target_scope: 'entity', target_types: ['Infrastructure'] })).toEqual(['Infrastructure']);
    expect(resolveKnowledgeDecayRuleTypes({ target_scope: 'indicator' })).toEqual([]);
  });

  it('should accept valid knowledge rules and ship valid built-in rules disabled', () => {
    expect(() => validateKnowledgeDecayRule(relationshipRule())).not.toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ target_types: [], freshness_policy: 'revoke' }))).not.toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ freshness_policy: 'lower_confidence', freshness_confidence_step: 15 }))).not.toThrow();
    BUILT_IN_KNOWLEDGE_DECAY_RULES.forEach((rule) => {
      expect(rule.active).toEqual(false);
      expect(() => validateKnowledgeDecayRule(rule)).not.toThrow();
    });
  });

  it('should reject invalid knowledge rules', () => {
    expect(() => validateKnowledgeDecayRule(relationshipRule({ target_scope: 'indicator' }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ stale_after_days: 0 }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ stale_after_days: 1.5 }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ target_types: ['Malware'] }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ freshness_policy: 'lower_confidence', freshness_confidence_step: 0 }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ decay_filters: '{not json' }))).toThrow();
    // Indicators keep their own decay, observables cannot be revoked
    expect(() => validateKnowledgeDecayRule(relationshipRule({ target_scope: 'entity', target_types: ['Indicator'] }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ target_scope: 'entity', target_types: [] }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ target_scope: 'entity', target_types: ['IPv4-Addr'], freshness_policy: 'revoke' }))).toThrow();
    expect(() => validateKnowledgeDecayRule(relationshipRule({ target_scope: 'entity', target_types: ['IPv4-Addr'] }))).not.toThrow();
  });

  it('should validate knowledge rule filters with the schema', () => {
    const filters = JSON.stringify({ mode: 'and', filters: [{ key: ['confidence'], values: ['50'], operator: 'gte' }], filterGroups: [] });
    expect(() => validateKnowledgeDecayRule(relationshipRule({ decay_filters: filters }))).not.toThrow();
    const unknownKey = JSON.stringify({ mode: 'and', filters: [{ key: ['not_an_attribute'], values: ['x'] }], filterGroups: [] });
    expect(() => validateKnowledgeDecayRule(relationshipRule({ decay_filters: unknownKey }))).toThrow();
  });

  it('should control the edition of decay rules by scope', () => {
    const indicatorRule = storedRule({ target_scope: 'indicator' });
    expect(checkDecayRulePatch(indicatorRule, [{ key: 'decay_lifetime', value: ['30'] }])).toEqual(false);
    expect(() => checkDecayRulePatch(indicatorRule, [{ key: 'stale_after_days', value: ['30'] }])).toThrow();
    expect(() => checkDecayRulePatch(storedRule({ target_scope: 'indicator', built_in: true }), [{ key: 'active', value: ['false'] }])).toThrow();
    const knowledgeRule = storedRule();
    expect(() => checkDecayRulePatch(knowledgeRule, [{ key: 'decay_pound', value: ['1'] }])).toThrow();
    expect(() => checkDecayRulePatch(knowledgeRule, [{ key: 'target_scope', value: ['entity'] }])).toThrow();
    // The date of the last configuration change decides which flags a run releases: only the platform sets it
    expect(() => checkDecayRulePatch(knowledgeRule, [{ key: 'freshness_configured_at', value: ['2020-01-01T00:00:00.000Z'] }])).toThrow();
    expect(() => checkDecayRulePatch(knowledgeRule, [{ key: 'stale_after_days', value: ['0'] }])).toThrow();
    expect(checkDecayRulePatch(knowledgeRule, [{ key: 'stale_after_days', value: ['400'] }])).toEqual(true);
    expect(checkDecayRulePatch(knowledgeRule, [{ key: 'name', value: ['Renamed'] }])).toEqual(false);
    // The knowledge flagged under the previous policy is evaluated again under the new one
    expect(checkDecayRulePatch(knowledgeRule, [{ key: 'freshness_policy', value: ['flag'] }])).toEqual(true);
    // A lowered priority lets an overlapping rule take over the knowledge the rule flagged
    expect(checkDecayRulePatch(knowledgeRule, [{ key: 'order', value: ['0'] }])).toEqual(true);
    // A new confidence step applies to the knowledge the rule already lowered
    const lowering = storedRule({ freshness_policy: 'lower_confidence', freshness_confidence_step: 10 });
    expect(checkDecayRulePatch(lowering, [{ key: 'freshness_confidence_step', value: ['20'] }])).toEqual(true);
    // Built-in knowledge rules ship disabled and can only be (de)activated
    const builtIn = storedRule({ built_in: true, active: false });
    expect(checkDecayRulePatch(builtIn, [{ key: 'active', value: ['true'] }])).toEqual(true);
    expect(() => checkDecayRulePatch(builtIn, [{ key: 'stale_after_days', value: ['10'] }])).toThrow();
  });

  it('should let a freshness run apply a rule only while the rule keeps the configuration the run loaded', () => {
    const loaded = storedRule({ freshness_policy: 'lower_confidence', freshness_confidence_step: 10 });
    expect(hasSameFreshnessConfiguration(loaded, storedRule({ freshness_policy: 'lower_confidence', freshness_confidence_step: 10 }))).toEqual(true);
    // A new name or description does not change what the run applies
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, name: 'Renamed', description: 'New description' })).toEqual(true);
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, stale_after_days: 30 })).toEqual(false);
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, freshness_policy: 'revoke' })).toEqual(false);
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, freshness_confidence_step: 20 })).toEqual(false);
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, active: false })).toEqual(false);
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, order: 2 })).toEqual(false);
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, target_types: ['uses', 'targets'] })).toEqual(false);
    expect(hasSameFreshnessConfiguration(loaded, { ...loaded, decay_filters: '{"mode":"and","filters":[],"filterGroups":[]}' })).toEqual(false);
    // A deleted rule applies to nothing
    expect(hasSameFreshnessConfiguration(loaded, undefined)).toEqual(false);
  });
});

describe('Knowledge freshness manager', () => {
  const prepared = (rule: BasicStoreEntityDecayRule, filters?: object) => ({
    rule,
    types: resolveKnowledgeDecayRuleTypes(rule),
    filters: filters as any,
  });

  it('should reconcile the stale flag with the assertions inherited from merged elements', () => {
    const reference = new Date('2026-10-11T00:00:00.000Z');
    const rules = [{ id: 'rule-30', stale_after_days: 30 }];
    const stale = { freshness_stale: true, freshness_stale_at: '2026-10-05T00:00:00.000Z', freshness_rule_id: 'rule-30' };
    // A source asserted the element after the stale decision
    expect(isFreshAfterMerge(stale, '2026-10-06T00:00:00.000Z', rules, reference)).toBe(true);
    // Older than the decision but within the delay of the rule
    expect(isFreshAfterMerge(stale, '2026-09-20T00:00:00.000Z', rules, reference)).toBe(true);
    // Still beyond the delay of the rule: the flag stays and the policy is not applied twice
    expect(isFreshAfterMerge(stale, '2026-08-01T00:00:00.000Z', rules, reference)).toBe(false);
    // The rule that flagged the element is no longer active
    expect(isFreshAfterMerge(stale, '2026-08-01T00:00:00.000Z', [], reference)).toBe(true);
    // Nothing to reconcile
    expect(isFreshAfterMerge({ freshness_stale: false }, '2026-10-06T00:00:00.000Z', rules, reference)).toBe(false);
    expect(isFreshAfterMerge(stale, undefined, rules, reference)).toBe(false);
  });

  it('should compute the stale cutoff from the number of days', () => {
    expect(computeStaleCutoff(10, new Date('2026-10-11T00:00:00.000Z'))).toEqual('2026-10-01T00:00:00.000Z');
  });

  it('should only select fresh, non revoked knowledge last asserted before the cutoff', () => {
    const ruleFilters = { mode: FilterMode.And, filters: [{ key: ['confidence'], values: ['50'], operator: FilterOperator.Gte }], filterGroups: [] };
    const filters = buildStaleCandidatesFilters('2026-01-01T00:00:00.000Z', ruleFilters);
    expect(filters.filters).toEqual([
      { key: ['last_asserted_at'], values: ['2026-01-01T00:00:00.000Z'], operator: FilterOperator.Lte },
      { key: ['freshness_stale'], values: ['true'], operator: FilterOperator.NotEq },
      { key: ['revoked'], values: ['true'], operator: FilterOperator.NotEq },
    ]);
    expect(filters.filterGroups).toEqual([ruleFilters]);
  });

  it('should let the highest priority rule handle the knowledge it targets', () => {
    const allRelationships = prepared(storedRule({ id: 'low', target_types: [] }));
    const uses = prepared(storedRule({ id: 'uses', target_types: ['uses'] }));
    const filteredUses = prepared(storedRule({ id: 'filtered', target_types: ['uses', 'targets'] }), { mode: 'and', filters: [], filterGroups: [] });
    const entities = prepared(storedRule({ id: 'entities', target_scope: 'entity', target_types: ['Infrastructure'] }));
    // A higher rule without filters removes its types
    const shadowed = computeRuleShadowing(allRelationships, [uses, entities]);
    expect(shadowed.types).not.toContain('uses');
    expect(shadowed.types).toContain('communicates-with');
    expect(shadowed.filteredHigherRules).toEqual([]);
    // A higher rule with filters is checked per candidate, on the overlapping types only
    const partially = computeRuleShadowing(allRelationships, [filteredUses]);
    expect(partially.types).toContain('uses');
    expect(partially.filteredHigherRules.map((rule) => rule.types)).toEqual([['uses', 'targets']]);
    // Rules of other scopes never shadow
    expect(computeRuleShadowing(entities, [allRelationships]).types).toEqual(['Infrastructure']);
    expect(computeRuleShadowing(uses, [prepared(storedRule({ id: 'other', target_types: ['uses'] }))]).types).toEqual([]);
  });

  it('should resume the scan of a rule after the last candidate it examined, and start over once the end is reached', () => {
    const lastExamined = ['indicator--examined'];
    // Stopped by the budget
    expect(resumeAfterScan({ applied: 10, scanned: 40, lastExamined }, 10, 100)).toEqual(lastExamined);
    // Stopped by the scan bound: candidates the run could not act on never hold back the ones after them
    expect(resumeAfterScan({ applied: 0, scanned: 100, lastExamined }, 10, 100)).toEqual(lastExamined);
    // The last candidate was reached
    expect(resumeAfterScan({ applied: 3, scanned: 40, lastExamined }, 10, 100)).toBeUndefined();
    expect(resumeAfterScan({ applied: 0, scanned: 0 }, 10, 100)).toBeUndefined();
  });

  it('should give every knowledge decay rule its share of a run before the backlog of a higher priority rule', async () => {
    // Rule 0 has a large backlog, rule 1 has 10 stale elements, rule 2 has 2
    const backlogs = [1000, 10, 2];
    const calls: Array<[number, number]> = [];
    const apply = async (index: number, budget: number) => {
      calls.push([index, budget]);
      const applied = Math.min(budget, backlogs[index]);
      backlogs[index] -= applied;
      return applied;
    };
    const { budget: left, nextStart } = await runWithFairShares(3, 90, apply, (index) => backlogs[index] > 0);
    // 30 each first, then what rules 1 and 2 left goes to rule 0, the only one with candidates left
    expect(calls).toEqual([[0, 30], [1, 30], [2, 30], [0, 48]]);
    expect(backlogs).toEqual([922, 0, 0]);
    expect(left).toEqual(0);
    // Every rule got its share: the next run starts with the highest priority rule again
    expect(nextStart).toEqual(0);
    expect(await runWithFairShares(0, 90, apply, () => true)).toEqual({ budget: 90, nextStart: 0 });
  });

  it('should serve every knowledge decay rule in turn when they outnumber the elements of a run', async () => {
    // Five rules with a backlog each and two elements per run: each run starts after the last rule the previous one served
    const served: number[] = [];
    const apply = async (index: number, budget: number) => {
      served.push(index);
      return Math.min(budget, 1);
    };
    let start = 0;
    for (let run = 0; run < 3; run += 1) {
      ({ nextStart: start } = await runWithFairShares(5, 2, apply, () => true, start));
    }
    expect(served).toEqual([0, 1, 2, 3, 4, 0]);
    expect(start).toEqual(1);
    // A rule without candidates costs nothing: the run moves on to the next rules
    served.length = 0;
    const sparse = await runWithFairShares(5, 2, async (index, budget) => {
      served.push(index);
      return index % 2 === 0 ? Math.min(budget, 1) : 0;
    }, () => false, 1);
    expect(served).toEqual([1, 2, 3, 4]);
    expect(sparse).toEqual({ budget: 0, nextStart: 0 });
    // Once the rules no longer outnumber the elements of a run, a rotated start is dropped: priority order again
    served.length = 0;
    const fewer = await runWithFairShares(3, 6, apply, () => false, 2);
    expect(served).toEqual([0, 1, 2]);
    expect(fewer).toEqual({ budget: 3, nextStart: 0 });
  });
});
