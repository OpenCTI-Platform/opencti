import { describe, expect, it } from 'vitest';
import { buildHistogramBreakdownAggregations } from '../../../src/database/engine';

const countOverTime = { date_histogram: { field: 'created_at', calendar_interval: 'day' } };

describe('buildHistogramBreakdownAggregations', () => {
  it('should count every key of a field and the documents carrying none of them', () => {
    const aggs = buildHistogramBreakdownAggregations({ field: 'rel_object-label.internal_id', keys: ['label-a', 'label-b'], withOther: true }, countOverTime);
    expect(aggs).toEqual({
      breakdown: {
        terms: { field: 'rel_object-label.internal_id.keyword', include: ['label-a', 'label-b'], size: 2 },
        aggs: { count_over_time: countOverTime },
      },
      other: {
        filter: { bool: { must_not: [{ terms: { 'rel_object-label.internal_id.keyword': ['label-a', 'label-b'] } }] } },
        aggs: { count_over_time: countOverTime },
      },
    });
  });

  it('should count everything in the Other series without key, and nothing else without Other', () => {
    expect(buildHistogramBreakdownAggregations({ field: 'entity_type', keys: [], withOther: true }, countOverTime)).toEqual({
      other: { filter: { match_all: {} }, aggs: { count_over_time: countOverTime } },
    });
    expect(buildHistogramBreakdownAggregations({ field: 'entity_type', keys: [], withOther: false }, countOverTime)).toEqual({});
  });

  it('should count the relationships by the type of one of their sides, from their connections', () => {
    const aggs = buildHistogramBreakdownAggregations({ field: 'connections.types', keys: ['malware', 'intrusion-set'], withOther: true, connectionSide: 'from' }, countOverTime) as any;
    const sideQuery = { query_string: { query: '*_from', fields: ['connections.role'] } };
    expect(aggs.breakdown).toEqual({
      nested: { path: 'connections' },
      aggs: {
        side: {
          filter: sideQuery,
          aggs: {
            types: {
              terms: { field: 'connections.types.keyword', include: ['malware', 'intrusion-set'], size: 2 },
              // Each type bucket counts the relationships themselves, on their own date
              aggs: { relationships: { reverse_nested: {}, aggs: { count_over_time: countOverTime } } },
            },
          },
        },
      },
    });
    // Other: the relationships whose source has none of the types
    expect(aggs.other).toEqual({
      filter: {
        bool: {
          must_not: [{
            nested: { path: 'connections', query: { bool: { must: [sideQuery, { terms: { 'connections.types.keyword': ['malware', 'intrusion-set'] } }] } } },
          }],
        },
      },
      aggs: { count_over_time: countOverTime },
    });
  });

  it('should read the side of the target from its role', () => {
    const aggs = buildHistogramBreakdownAggregations({ field: 'connections.types', keys: ['sector'], connectionSide: 'to' }, countOverTime) as any;
    expect(aggs.breakdown.aggs.side.filter).toEqual({ query_string: { query: '*_to', fields: ['connections.role'] } });
    expect(aggs.other).toBeUndefined();
  });
});
