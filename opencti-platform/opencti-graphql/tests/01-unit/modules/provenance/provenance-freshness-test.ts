import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import {
  BUILT_IN_KNOWLEDGE_DECAY_RULES,
  checkDecayRulePatch,
  getDecayRuleScope,
  isKnowledgeDecayRule,
  type KnowledgeDecayRuleDefinition,
  resolveKnowledgeDecayRuleTypes,
  validateKnowledgeDecayRule,
} from '../../../../src/modules/decayRule/decayRule-knowledge';
import type { BasicStoreEntityDecayRule } from '../../../../src/modules/decayRule/decayRule-types';
import { STIX_CORE_RELATIONSHIPS } from '../../../../src/schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import { buildStaleCandidatesFilters, computeRuleShadowing, computeStaleCutoff, isFreshAfterMerge } from '../../../../src/modules/provenance/provenance-freshness';

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
    expect(() => checkDecayRulePatch(knowledgeRule, [{ key: 'stale_after_days', value: ['0'] }])).toThrow();
    expect(checkDecayRulePatch(knowledgeRule, [{ key: 'stale_after_days', value: ['400'] }])).toEqual(true);
    expect(checkDecayRulePatch(knowledgeRule, [{ key: 'name', value: ['Renamed'] }])).toEqual(false);
    // Built-in knowledge rules ship disabled and can only be (de)activated
    const builtIn = storedRule({ built_in: true, active: false });
    expect(checkDecayRulePatch(builtIn, [{ key: 'active', value: ['true'] }])).toEqual(true);
    expect(() => checkDecayRulePatch(builtIn, [{ key: 'stale_after_days', value: ['10'] }])).toThrow();
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
});
