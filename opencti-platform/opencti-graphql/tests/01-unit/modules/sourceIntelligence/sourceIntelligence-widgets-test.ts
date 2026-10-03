import { describe, expect, it } from 'vitest';
import { aggregateValues } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-widgets';
import type { ScorecardAggregation } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-store';

describe('Source intelligence widget aggregations', () => {
  it('should compute every supported aggregation mode', () => {
    const values = [4, 1, 7, 2];
    expect(aggregateValues(values, 'sum')).toEqual(14);
    expect(aggregateValues(values, 'avg')).toEqual(3.5);
    expect(aggregateValues(values, 'min')).toEqual(1);
    expect(aggregateValues(values, 'max')).toEqual(7);
  });

  it('should return null without values', () => {
    expect(aggregateValues([], 'sum')).toBeNull();
    expect(aggregateValues([], 'max')).toBeNull();
  });

  it('should reject an unknown aggregation mode', () => {
    expect(() => aggregateValues([1], 'median' as ScorecardAggregation)).toThrowError('Unknown source scorecard aggregation');
  });
});
