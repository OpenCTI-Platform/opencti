import { describe, expect, it } from 'vitest';
import { isRequirementDeleted, isRescanSince, markRequirementDeleted, markRequirementRescan } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-lifecycle';
import { isBriefDue } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-brief';
import { computeMatchScore, type IrScoreResult, parseMatchHistory, topReasons } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-scoring';
import { isInRequirement } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import { parseIrFilters, typesOverlap } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-config';
import type { BasicStoreEntityIntelligenceRequirement, ParsedIntelligenceRequirement } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-types';
import type { BasicStoreEntityIntelligenceRequirementMatch } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

describe('Intelligence requirement lifecycle', () => {
  it('should remember a deleted requirement', () => {
    expect(isRequirementDeleted('ir-lifecycle-1')).toBe(false);
    markRequirementDeleted('ir-lifecycle-1');
    expect(isRequirementDeleted('ir-lifecycle-1')).toBe(true);
  });

  it('should tell whether a rescan was requested since a batch started', () => {
    const before = Date.now() - 1000;
    expect(isRescanSince('ir-lifecycle-2', before)).toBe(false);
    markRequirementRescan('ir-lifecycle-2');
    expect(isRescanSince('ir-lifecycle-2', before)).toBe(true);
    expect(isRescanSince('ir-lifecycle-2', Date.now() + 60000)).toBe(false);
  });
});

describe('Intelligence requirement brief schedule', () => {
  const ir = (frequency: string | undefined, last?: string) => ({ ir_brief_frequency: frequency, ir_last_brief_at: last } as unknown as BasicStoreEntityIntelligenceRequirement);
  const now = new Date('2026-11-21T12:00:00Z').getTime();

  it('should never be due when briefs are off or unset', () => {
    expect(isBriefDue(ir('off'), now)).toBe(false);
    expect(isBriefDue(ir(undefined), now)).toBe(false);
  });

  it('should be due when no brief was ever generated', () => {
    expect(isBriefDue(ir('daily'), now)).toBe(true);
    expect(isBriefDue(ir('weekly'), now)).toBe(true);
  });

  it('should follow the period since the last brief', () => {
    expect(isBriefDue(ir('daily', '2026-11-21T00:00:00Z'), now)).toBe(false);
    expect(isBriefDue(ir('daily', '2026-11-20T11:00:00Z'), now)).toBe(true);
    expect(isBriefDue(ir('weekly', '2026-11-18T12:00:00Z'), now)).toBe(false);
    expect(isBriefDue(ir('weekly', '2026-11-13T12:00:00Z'), now)).toBe(true);
  });
});

describe('Intelligence requirement match helpers', () => {
  it('should be part of the requirement only when auto or accepted and eligible', () => {
    expect(isInRequirement({ match_status: 'auto' })).toBe(true);
    expect(isInRequirement({ match_status: 'accepted', match_excluded: false })).toBe(true);
    expect(isInRequirement({ match_status: 'accepted', match_excluded: true })).toBe(false);
    expect(isInRequirement({ match_status: 'proposed' })).toBe(false);
    expect(isInRequirement({ match_status: 'rejected' })).toBe(false);
  });

  it('should read a stored history and tolerate a broken one', () => {
    expect(parseMatchHistory({ match_history: '[{"at":"2026-11-21","score":10}]' })).toHaveLength(1);
    expect(parseMatchHistory({ match_history: '{"not":"a list"}' })).toEqual([]);
    expect(parseMatchHistory({ match_history: 'not json' })).toEqual([]);
    expect(parseMatchHistory({ match_history: null })).toEqual([]);
  });

  it('should keep the three strongest reasons, signed', () => {
    const result: IrScoreResult = {
      score: 70,
      excluded: false,
      breakdown: [
        { rule_id: 'a', name: 'KEV', points: 40, hit: true, reason: '', kind: 'rule' },
        { rule_id: 'b', name: 'Old', points: -30, hit: true, reason: '', kind: 'rule' },
        { rule_id: 'c', name: 'CVSS', points: 20, hit: true, reason: '', kind: 'rule' },
        { rule_id: 'd', name: 'EPSS', points: 10, hit: true, reason: '', kind: 'rule' },
        { rule_id: 'e', name: 'Missed', points: 0, hit: false, reason: 'condition not met', kind: 'rule' },
      ],
    };
    expect(topReasons(result)).toEqual(['KEV +40', 'Old -30', 'CVSS +20']);
  });
});

describe('Intelligence requirement score without reads', () => {
  const context = {} as AuthContext;
  const user = {} as AuthUser;
  const match = (types: string, criteria: string[] = []) => ({
    id: 'm1',
    match_entity_id: 'e1',
    match_entity_type: types,
    match_criteria_ids: criteria,
    match_status: 'auto',
  } as unknown as BasicStoreEntityIntelligenceRequirementMatch);
  const rule = (id: string, points: number, types: string[], enabled = true) => ({
    id, name: id, points, enabled, required: false, applies_to_types: types, applies_to_criterion_id: null, filters: null, link: null, path_condition: null,
  });

  it('should score 0 and stay eligible when no rule applies to the type', async () => {
    const ir = { ir_scope_criteria: [], ir_relevance_rules: [rule('r1', 40, ['Report'])] } as unknown as ParsedIntelligenceRequirement;
    const result = await computeMatchScore(context, user, ir, match('Vulnerability'));
    expect(result.score).toBe(0);
    expect(result.excluded).toBe(false);
    expect(result.breakdown).toEqual([expect.objectContaining({ rule_id: 'r1', hit: false, reason: 'not applicable' })]);
  });

  it('should ignore disabled rules', async () => {
    const ir = { ir_scope_criteria: [], ir_relevance_rules: [rule('r1', 40, ['Vulnerability'], false)] } as unknown as ParsedIntelligenceRequirement;
    const result = await computeMatchScore(context, user, ir, match('Vulnerability'));
    expect(result.breakdown).toEqual([]);
  });

  it('should keep a match eligible when its criterion has no condition for its type', async () => {
    const ir = {
      ir_scope_criteria: [{ id: 'c1', name: 'c1', conditions: [{ id: 'k1', name: 'k1', applies_to_types: ['Report'], filters: null, link: null, path_condition: null }] }],
      ir_relevance_rules: [],
    } as unknown as ParsedIntelligenceRequirement;
    const result = await computeMatchScore(context, user, ir, match('Vulnerability', ['c1']));
    expect(result.excluded).toBe(false);
  });
});

describe('Intelligence requirement config helpers', () => {
  it('should parse stored filters and tolerate empty or broken values', () => {
    expect(parseIrFilters(null)).toBeNull();
    expect(parseIrFilters('')).toBeNull();
    expect(parseIrFilters('not json')).toBeNull();
    expect(parseIrFilters('{"mode":"and","filters":[],"filterGroups":[]}')).toEqual({ mode: 'and', filters: [], filterGroups: [] });
  });

  it('should treat an empty list of types as any type', () => {
    expect(typesOverlap([], ['Malware'])).toBe(true);
    expect(typesOverlap(['Malware'], [])).toBe(true);
    expect(typesOverlap(['Malware'], ['Malware'])).toBe(true);
    expect(typesOverlap(['Malware'], ['Vulnerability'])).toBe(false);
  });
});
