import { describe, expect, it } from 'vitest';
import { type DefenseGapView, matchGapFilter } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';

const gapAtLevel = (level: number) => ({
  level,
  recommended_action: 'validate',
  kill_chain_phase_ids: [],
  threats_count: 0,
  x_mitre_id: 'T1059',
  attack_pattern_name: 'Command and Scripting Interpreter',
  platform: null,
} as unknown as DefenseGapView);

describe('Defense gaps filter', () => {
  it('should keep the open levels only, without a level filter', () => {
    expect([0, 1, 2, 3, 4].filter((level) => matchGapFilter(gapAtLevel(level), null))).toEqual([0, 1, 2, 3]);
    expect([0, 1, 2, 3, 4].filter((level) => matchGapFilter(gapAtLevel(level), { levels: [] }))).toEqual([0, 1, 2, 3]);
  });

  it('should never let a level filter bring a validated technique into the gaps', () => {
    expect(matchGapFilter(gapAtLevel(4), { levels: [4] })).toBe(false);
    expect([2, 3, 4].filter((level) => matchGapFilter(gapAtLevel(level), { levels: [3, 4] }))).toEqual([3]);
  });
});
