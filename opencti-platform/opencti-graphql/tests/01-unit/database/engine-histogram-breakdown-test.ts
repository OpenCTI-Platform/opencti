import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// The search requests are answered by a stub of the Elasticsearch client
const { elkSearch, FakeElkClient, FakeOpenClient } = vi.hoisted(() => {
  const elkSearchFn = vi.fn();
  class ElkClientStub {
    search = elkSearchFn;

    ingest = { putPipeline: vi.fn(async () => ({})) };

    info = vi.fn(async () => ({ version: { distribution: 'elasticsearch', number: '8.19.0' }, tagline: 'You Know, for Search' }));
  }
  class OpenClientStub {}
  return { elkSearch: elkSearchFn, FakeElkClient: ElkClientStub, FakeOpenClient: OpenClientStub };
});

vi.mock('@elastic/elasticsearch', () => ({ Client: FakeElkClient }));
vi.mock('@opensearch-project/opensearch', () => ({ Client: FakeOpenClient }));
vi.mock('@opensearch-project/opensearch/aws', () => ({ AwsSigv4Signer: vi.fn(() => ({})) }));

import conf from '../../../src/config/conf';
import {
  buildHistogramBreakdownAggregations,
  elAggregationCount,
  elAggregationRanking,
  elConnectionTypesRanking,
  elHistogramBreakdownCount,
  elKeywordWrittenForms,
  MAX_AGGREGATION_SIZE,
  MAX_EXACT_RANKING_SIZE,
  searchEngineInit,
} from '../../../src/database/engine';
import { SYSTEM_USER } from '../../../src/utils/access';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { CLIENT_ABORT_ERROR, DATABASE_ERROR } from '../../../src/config/errors';
import type { AuthContext } from '../../../src/types/user';

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

  it('should filter every key of a field with many values on its own', () => {
    const aggs = buildHistogramBreakdownAggregations({ field: 'creator_id', keys: ['user.a', 'user-b'], filterPerKey: true }, countOverTime) as any;
    // Keyed by position: a value with dots never becomes a field name of the response
    expect(aggs.breakdown.filters.filters).toEqual({ k0: { term: { 'creator_id.keyword': 'user.a' } }, k1: { term: { 'creator_id.keyword': 'user-b' } } });
  });

  it('should keep the terms restricted to the keys for a side of the relationships, whatever the filter per key', () => {
    const aggs = buildHistogramBreakdownAggregations({ field: 'connections.types', keys: ['malware'], filterPerKey: true, connectionSide: 'from' }, countOverTime) as any;
    expect(aggs.breakdown.nested).toEqual({ path: 'connections' });
    expect(aggs.breakdown.aggs.side.aggs.types.terms).toEqual({ field: 'connections.types.keyword', include: ['malware'], size: 1 });
  });

  it('should read the side of the target from its role', () => {
    const aggs = buildHistogramBreakdownAggregations({ field: 'connections.types', keys: ['sector'], connectionSide: 'to' }, countOverTime) as any;
    expect(aggs.breakdown.aggs.side.filter).toEqual({ query_string: { query: '*_to', fields: ['connections.role'] } });
    expect(aggs.other).toBeUndefined();
  });
});

const context = { source: 'test' } as AuthContext;
// A request aborted by its client before reaching the engine
const abortedContext = () => {
  const controller = new AbortController();
  controller.abort();
  return { ...context, requestAbortSignal: controller.signal } as AuthContext;
};
const searchResponse = (aggregations: Record<string, unknown>) => ({ _shards: { total: 2, successful: 2, failed: 0 }, aggregations });
const lastSearchBody = () => elkSearch.mock.lastCall?.[0].body;

describe('engine: requests of the time series breakdowns', () => {
  beforeAll(async () => {
    const realGet = conf.get.bind(conf);
    vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
      // The stubbed Elasticsearch 8 client, without probing a server
      if (key === 'elasticsearch:engine_client') return 'elasticsearch8';
      return realGet(key as string);
    });
    await searchEngineInit();
  });

  beforeEach(() => {
    elkSearch.mockReset();
  });

  describe('elAggregationRanking', () => {
    const rank = (rankingOrder: 'asc' | 'desc') => elAggregationRanking(context, SYSTEM_USER, 'index', { field: 'creator_id', rankingOrder });
    const genres = (sumOtherDocCount: number) => searchResponse({
      genres: {
        sum_other_doc_count: sumOtherDocCount,
        buckets: [{ key: 'user-a', doc_count: 3, weight: { value: 3 } }, { key: 'user-b', doc_count: 2, weight: { value: 7 } }],
      },
    });
    const weight = { weight: { sum: { field: 'i_inference_weight', missing: 1 } } };

    it('should rank every value of every shard on its weighted total for the lowest values', async () => {
      elkSearch.mockResolvedValue(genres(0));

      const ranking = await rank('asc');

      expect(lastSearchBody().aggs.genres).toEqual({
        terms: { field: 'creator_id.keyword', size: MAX_EXACT_RANKING_SIZE, shard_size: MAX_EXACT_RANKING_SIZE, order: { weight: 'asc' } },
        aggs: weight,
      });
      // The value is the weighted total, as the series count it, not the number of documents
      expect(ranking).toEqual({
        sumOtherDocCount: 0,
        buckets: [
          { key: 'user-a', label: 'user-a', value: 3, count: 3 },
          { key: 'user-b', label: 'user-b', value: 7, count: 2 },
        ],
      });
    });

    it('should keep the top values of each shard on their weighted total for the highest values', async () => {
      // Values left out are expected in desc: they are below the ones kept, and counted
      elkSearch.mockResolvedValue(genres(12));

      const ranking = await rank('desc');

      expect(lastSearchBody().aggs.genres).toEqual({
        terms: { field: 'creator_id.keyword', size: MAX_AGGREGATION_SIZE, order: { weight: 'desc' } },
        aggs: weight,
      });
      expect(ranking.buckets).toHaveLength(2);
      expect(ranking.sumOtherDocCount).toEqual(12);
    });

    it('should refuse the lowest values when a value was left out, the ranking being no longer exact', async () => {
      elkSearch.mockResolvedValue(genres(1));

      await expect(rank('asc')).rejects.toMatchObject({
        extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_many_values', max: MAX_EXACT_RANKING_SIZE } },
      });
    });

    it('should keep a request aborted by its client a client abort', async () => {
      await expect(elAggregationRanking(abortedContext(), SYSTEM_USER, 'index', { field: 'creator_id', rankingOrder: 'desc' }))
        .rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
      expect(elkSearch).not.toHaveBeenCalled();
    });
  });

  describe('elAggregationCount', () => {
    it('should keep the request of the distributions: the top values by documents, with the missing bucket', async () => {
      elkSearch.mockResolvedValue(searchResponse({
        genres: { sum_other_doc_count: 5, buckets: [{ key: 'malware', doc_count: 2, weight: { value: 2 } }] },
      }));

      const distribution = await elAggregationCount(context, SYSTEM_USER, 'index', { field: 'entity_type' });

      expect(distribution).toEqual([{ key: 'malware', label: 'Malware', value: 2, count: 2 }]);
      expect(lastSearchBody().aggs.genres).toEqual({
        terms: { field: 'entity_type.keyword', size: MAX_AGGREGATION_SIZE, missing: 'unknown' },
        aggs: { weight: { sum: { field: 'i_inference_weight', missing: 1 } } },
      });
    });
  });

  describe('elConnectionTypesRanking', () => {
    const rankTypes = (rankingOrder: 'asc' | 'desc', ctx = context) => elConnectionTypesRanking(ctx, SYSTEM_USER, 'index', {
      connectionSide: 'from',
      rankingOrder,
    });
    const typeBucket = (key: string, count: number, weight: number) => ({ key, doc_count: count, relationships: { doc_count: count, weight: { value: weight } } });
    const connections = (sumOtherDocCount: number) => searchResponse({
      connections: { side: { types: { sum_other_doc_count: sumOtherDocCount, buckets: [typeBucket('malware', 2, 5)] } } },
    });
    const typesOf = (body: any) => body.aggs.connections.aggs.side.aggs.types;

    it('should rank every type of every shard on the weighted total of its relationships for the lowest types, the abstract ones excluded', async () => {
      elkSearch.mockResolvedValue(connections(0));

      const ranking = await rankTypes('asc');

      expect(typesOf(lastSearchBody())).toEqual({
        terms: {
          field: 'connections.types.keyword',
          size: MAX_EXACT_RANKING_SIZE,
          shard_size: MAX_EXACT_RANKING_SIZE,
          order: { 'relationships>weight': 'asc' },
          exclude: expect.arrayContaining(['stix-domain-object', 'basic-object']),
        },
        // The weight of the relationships themselves, reached back from their connection
        aggs: { relationships: { reverse_nested: {}, aggs: { weight: { sum: { field: 'i_inference_weight', missing: 1 } } } } },
      });
      expect(ranking).toEqual({ sumOtherDocCount: 0, buckets: [{ key: 'malware', label: 'Malware', value: 5, count: 2 }] });
    });

    it('should name the types after their registered type', async () => {
      vi.spyOn(schemaAttributesDefinition, 'getRegisteredTypes').mockReturnValue(['IMEI', 'SecurityPlatform', 'Intrusion-Set', 'uses']);
      elkSearch.mockResolvedValue(searchResponse({
        connections: {
          side: {
            types: {
              sum_other_doc_count: 0,
              buckets: ['imei', 'securityplatform', 'intrusion-set', 'uses', 'ipv4-addr'].map((key) => typeBucket(key, 1, 1)),
            },
          },
        },
      }));

      const { buckets } = await rankTypes('desc');

      // A name of no registered type keeps the label converted from it
      expect(buckets.map(({ label }) => label)).toEqual(['IMEI', 'SecurityPlatform', 'Intrusion-Set', 'uses', 'IPv4-Addr']);
      vi.restoreAllMocks();
    });

    it('should keep the top types of each shard for the highest types', async () => {
      elkSearch.mockResolvedValue(connections(4));

      await expect(rankTypes('desc')).resolves.toMatchObject({ sumOtherDocCount: 4, buckets: [{ key: 'malware' }] });

      const { terms } = typesOf(lastSearchBody());
      expect(terms).toMatchObject({ field: 'connections.types.keyword', size: MAX_AGGREGATION_SIZE, order: { 'relationships>weight': 'desc' } });
      expect(terms.shard_size).toBeUndefined();
    });

    it('should refuse the lowest types when a type was left out', async () => {
      elkSearch.mockResolvedValue(connections(3));

      await expect(rankTypes('asc')).rejects.toMatchObject({
        extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_many_values', max: MAX_EXACT_RANKING_SIZE } },
      });
    });

    it('should keep a request aborted by its client a client abort', async () => {
      await expect(rankTypes('desc', abortedContext())).rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
      expect(elkSearch).not.toHaveBeenCalled();
    });

    it('should report an engine failure as a database error', async () => {
      elkSearch.mockRejectedValue(new Error('index_not_found_exception'));

      await expect(rankTypes('desc')).rejects.toMatchObject({ extensions: { code: DATABASE_ERROR } });
    });
  });

  describe('elKeywordWrittenForms', () => {
    const categoryFilter = { mode: 'and', filters: [{ key: ['category'], values: ['report_types_ov'] }], filterGroups: [] } as any;
    const writtenForms = (keys: string[]) => elKeywordWrittenForms(context, SYSTEM_USER, 'index', {
      types: ['Vocabulary'],
      filters: categoryFilter,
      noFiltersChecking: true,
      field: 'name',
      keys,
    });

    it('should match the keys on the indexed form of the field, and read one written form of each', async () => {
      elkSearch.mockResolvedValue(searchResponse({ keys: { buckets: [] } }));
      const keys = ['высокий', 'strasse', 'ħ ŋ ĳ ſ ﬁ ｆｕｌｌ'];

      await writtenForms(keys);

      const body = lastSearchBody();
      expect(body.size).toEqual(0);
      // The keys are the indexed forms already: the engine compares them to the normalized name as they are
      expect(body.aggs).toEqual({
        keys: {
          terms: { field: 'name.keyword', include: keys, size: 3 },
          aggs: { written: { top_hits: { size: 1, _source: ['name'] } } },
        },
      });
      // Restricted to the vocabularies of the category
      expect(JSON.stringify(body.query)).toContain('report_types_ov');
      expect(JSON.stringify(body.query)).toContain('Vocabulary');
    });

    it('should map every indexed form found to its written form, and only them', async () => {
      elkSearch.mockResolvedValue(searchResponse({
        keys: {
          buckets: [
            { key: 'высокий', doc_count: 1, written: { hits: { hits: [{ _source: { name: 'Высокий' } }] } } },
            { key: 'strasse', doc_count: 2, written: { hits: { hits: [{ _source: { name: 'Straße' } }] } } },
          ],
        },
      }));

      const names = await writtenForms(['высокий', 'strasse', 'not-a-vocabulary']);

      expect(names).toEqual(new Map([['высокий', 'Высокий'], ['strasse', 'Straße']]));
    });

    it('should not query anything without key', async () => {
      await expect(writtenForms([])).resolves.toEqual(new Map());
      expect(elkSearch).not.toHaveBeenCalled();
    });

    it('should report an engine failure as a database error', async () => {
      elkSearch.mockRejectedValue(new Error('index_not_found_exception'));

      await expect(writtenForms(['p1'])).rejects.toMatchObject({ extensions: { code: DATABASE_ERROR } });
    });
  });

  describe('elHistogramBreakdownCount', () => {
    const points = (value: number) => ({ '2026-01-01': { weight: { value } } });

    it('should return the Other histogram apart, even beside a value named like a reserved key', async () => {
      elkSearch.mockResolvedValue(searchResponse({
        breakdown: {
          buckets: [
            { key: '__other__', count_over_time: { buckets: points(4) } },
            { key: 'label-b', count_over_time: { buckets: points(1) } },
          ],
        },
        other: { count_over_time: { buckets: points(7) } },
      }));

      const { histograms, other } = await elHistogramBreakdownCount(context, SYSTEM_USER, 'index', {
        field: 'rel_object-label.internal_id',
        interval: 'day',
        keys: ['__other__', 'label-b'],
        withOther: true,
      });

      expect(histograms).toEqual(new Map([['__other__', [{ date: '2026-01-01', value: 4 }]], ['label-b', [{ date: '2026-01-01', value: 1 }]]]));
      expect(other).toEqual([{ date: '2026-01-01', value: 7 }]);
    });

    it('should only ask for the aggregations, without any document', async () => {
      elkSearch.mockResolvedValue(searchResponse({}));

      await elHistogramBreakdownCount(context, SYSTEM_USER, 'index', { field: 'creator_id', interval: 'day', keys: ['user-a'] });

      const request = elkSearch.mock.lastCall?.[0];
      expect(request.body.size).toEqual(0);
      expect(request._source_excludes).toBeUndefined();
    });

    it('should not return any Other histogram unless it is requested', async () => {
      elkSearch.mockResolvedValue(searchResponse({ breakdown: { buckets: [{ key: 'label-a', count_over_time: { buckets: points(2) } }] } }));

      const { other } = await elHistogramBreakdownCount(context, SYSTEM_USER, 'index', { field: 'rel_object-label.internal_id', interval: 'day', keys: ['label-a'] });

      expect(other).toBeNull();
    });

    it('should keep a request aborted by its client a client abort', async () => {
      const options = { field: 'creator_id', interval: 'day', keys: ['user-a'] };
      await expect(elHistogramBreakdownCount(abortedContext(), SYSTEM_USER, 'index', options)).rejects.toMatchObject({ extensions: { code: CLIENT_ABORT_ERROR } });
      expect(elkSearch).not.toHaveBeenCalled();

      elkSearch.mockRejectedValue(new Error('index_not_found_exception'));
      await expect(elHistogramBreakdownCount(context, SYSTEM_USER, 'index', options)).rejects.toMatchObject({ extensions: { code: DATABASE_ERROR } });
    });
  });
});
