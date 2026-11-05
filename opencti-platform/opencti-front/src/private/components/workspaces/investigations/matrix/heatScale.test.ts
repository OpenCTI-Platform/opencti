import { describe, expect, it } from 'vitest';
import { computeHeatScale, heatBorder, heatFill, heatStopIndex, HEAT_STOPS } from './heatScale';
import type { TechniqueUsage } from './matrixTypes';

const usage = (attackPatternId: string, score: number): TechniqueUsage => ({
  attackPatternId,
  score,
  linkedEntities: [],
});

const toMap = (entries: TechniqueUsage[]) => new Map(entries.map((entry) => [entry.attackPatternId, entry]));

describe('computeHeatScale', () => {
  it('takes the max score over the ids in the kill chain set', () => {
    const scale = computeHeatScale(
      toMap([usage('ap1', 2), usage('ap2', 4), usage('ap3', 3)]),
      new Set(['ap1', 'ap2', 'ap3']),
    );
    expect(scale.max).toBe(4);
  });

  it('ignores a high score outside the kill chain set', () => {
    const scale = computeHeatScale(
      toMap([usage('ap1', 2), usage('ap-outside', 9)]),
      new Set(['ap1']),
    );
    expect(scale.max).toBe(2);
  });

  it('returns 0 when no scored id is in the kill chain set', () => {
    expect(computeHeatScale(toMap([usage('ap-outside', 9)]), new Set(['ap1'])).max).toBe(0);
    expect(computeHeatScale(new Map(), new Set(['ap1'])).max).toBe(0);
  });
});

describe('heatStopIndex', () => {
  it('gives every scored cell the first stop when max is 1', () => {
    expect(heatStopIndex(1, { max: 1 })).toBe(0);
  });

  it('maps scores 1 to 5 over a max of 5 onto indexes 0 to 4', () => {
    const scale = { max: 5 };
    expect([1, 2, 3, 4, 5].map((score) => heatStopIndex(score, scale))).toEqual([0, 1, 2, 3, 4]);
  });

  it('maps score 2 over a max of 2 onto index 4 and score 1 onto index 0', () => {
    const scale = { max: 2 };
    expect(heatStopIndex(2, scale)).toBe(4);
    expect(heatStopIndex(1, scale)).toBe(0);
  });

  it('clamps scores outside [1, max] to 0..4', () => {
    expect(heatStopIndex(0, { max: 5 })).toBe(0);
    expect(heatStopIndex(-3, { max: 5 })).toBe(0);
    expect(heatStopIndex(9, { max: 5 })).toBe(4);
  });
});

describe('heat colours', () => {
  it('uses the five heat stop tokens in order', () => {
    expect(HEAT_STOPS).toEqual([
      'var(--yellow-300)',
      'var(--yellow-500)',
      'var(--orange-400)',
      'var(--orange-500)',
      'var(--red-400)',
    ]);
  });

  it('fills with the stop at 70% over transparent', () => {
    expect(heatFill(4)).toBe('color-mix(in srgb, var(--red-400) 70%, transparent)');
  });

  it('borders with the solid stop', () => {
    expect(heatBorder(0)).toBe('var(--yellow-300)');
    expect(heatBorder(4)).toBe('var(--red-400)');
  });
});
