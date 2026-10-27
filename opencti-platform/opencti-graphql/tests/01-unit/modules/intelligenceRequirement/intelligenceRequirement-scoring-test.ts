import { describe, expect, it } from 'vitest';
import { diffOutcomes, type IrRuleOutcome } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-scoring';

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
