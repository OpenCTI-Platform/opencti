import { describe, expect, it } from 'vitest';
import { createMatchWriter, diffOutcomes, type IrRuleOutcome, isCandidateEligible } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-scoring';
import type { BasicStoreEntityIntelligenceRequirementMatch } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import { conditionedCriteriaFor } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-engine';
import type { ParsedIntelligenceRequirement } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const rule = (rule_id: string, name: string, points: number, hit: boolean, reason = ''): IrRuleOutcome => ({ rule_id, name, points: hit ? points : 0, hit, reason, kind: 'rule' });
const condition = (rule_id: string, name: string, hit: boolean): IrRuleOutcome => ({ rule_id, name, points: 0, hit, reason: hit ? '' : 'scope condition not met', kind: 'condition', criterion_id: 'c1' });

describe('Intelligence requirement score history', () => {
  it('should describe a first evaluation by what holds: rules giving points, conditions not met', () => {
    const next = [condition('k-eu', 'Targets Europe', false), condition('k-recent', 'Seen recently', true), rule('r-kev', 'In CISA KEV', 40, true), rule('r-cvss', 'CVSS 9', 20, false)];
    expect(diffOutcomes([], next)).toEqual(['Targets Europe: not met', 'In CISA KEV +40']);
  });

  it('should describe a re-evaluation by what changed', () => {
    const previous = [condition('k-eu', 'Targets Europe', false), rule('r-kev', 'In CISA KEV', 40, false), rule('r-cvss', 'CVSS 9', 20, true)];
    const next = [condition('k-eu', 'Targets Europe', true), rule('r-kev', 'In CISA KEV', 40, true), { ...rule('r-cvss', 'CVSS 9', 20, false), points: 0 }];
    // A rule that stops matching loses the points it gave
    previous[2].points = 20;
    expect(diffOutcomes(previous, next)).toEqual(['Targets Europe: met', 'In CISA KEV +40', 'CVSS 9 -20']);
  });

  it('should ignore the rules that do not apply to the entity', () => {
    expect(diffOutcomes([], [rule('r-kev', 'In CISA KEV', 40, false, 'not applicable')])).toEqual([]);
  });
});

describe('Intelligence requirement on-demand eligibility', () => {
  const criterion = (id: string, kind: string, targetTypes: string[], conditionTypes: string[] | null) => ({
    id,
    name: id,
    kind,
    mode: 'auto',
    target_types: targetTypes,
    from_group_ids: [],
    relationship_types: [],
    direction: 'outgoing',
    conditions: conditionTypes ? [{ id: `${id}-k`, name: 'Recent', applies_to_types: conditionTypes, filters: null, link: null, path_condition: null }] : [],
  });
  const ir = {
    id: 'ir',
    ir_scope_criteria: [
      criterion('c-free', 'graph', ['Vulnerability'], null),
      criterion('c-recent', 'graph', ['Vulnerability'], ['Vulnerability']),
      criterion('c-reports', 'graph', ['Report'], ['Report']),
      criterion('c-any', 'attribute', [], []),
    ],
  } as unknown as ParsedIntelligenceRequirement;

  it('should only re-evaluate the criteria whose conditions apply to the type', () => {
    expect(conditionedCriteriaFor(ir, 'Vulnerability').map((c) => c.id)).toEqual(['c-recent', 'c-any']);
    expect(conditionedCriteriaFor(ir, 'Report').map((c) => c.id)).toEqual(['c-reports', 'c-any']);
  });

  it('should admit at once a candidate of a criterion without condition for its type', async () => {
    const context = {} as AuthContext;
    const user = {} as AuthUser;
    await expect(isCandidateEligible(context, user, ir, { id: 'v1', type: 'Vulnerability' }, 'c-free')).resolves.toBe(true);
    await expect(isCandidateEligible(context, user, ir, { id: 'v1', type: 'Vulnerability' }, 'c-reports')).resolves.toBe(true);
  });
});

describe('Intelligence requirement grouped writes', () => {
  it('should merge the writes of a batch and give them to a match read again', () => {
    const writer = createMatchWriter();
    const match = { id: 'm1', _index: 'idx', match_score: 10, match_history: '[]' } as unknown as BasicStoreEntityIntelligenceRequirementMatch;
    writer.write(match, { match_score: 30 });
    writer.write(match, { match_history: '[{"score":30}]' });
    const readAgain = { id: 'm1', _index: 'idx', match_score: 10, match_history: '[]' } as unknown as BasicStoreEntityIntelligenceRequirementMatch;
    writer.overlay(readAgain);
    expect(readAgain.match_score).toBe(30);
    expect(readAgain.match_history).toBe('[{"score":30}]');
  });

  it('should drop the writes of a match that left the requirement', () => {
    const writer = createMatchWriter();
    const match = { id: 'm1', _index: 'idx', match_score: 10 } as unknown as BasicStoreEntityIntelligenceRequirementMatch;
    writer.write(match, { match_score: 30 });
    writer.discard('m1');
    const readAgain = { id: 'm1', _index: 'idx', match_score: 10 } as unknown as BasicStoreEntityIntelligenceRequirementMatch;
    writer.overlay(readAgain);
    expect(readAgain.match_score).toBe(10);
  });
});
