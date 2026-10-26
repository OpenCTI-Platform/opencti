import { beforeEach, describe, expect, it, vi } from 'vitest';

const { elkSearch, openSearch, FakeElkClient, FakeOpenClient } = vi.hoisted(() => {
  const elkSearchFn = vi.fn();
  const openSearchFn = vi.fn();
  class ElkClientStub {
    search = elkSearchFn;

    ingest = { putPipeline: vi.fn(async () => ({})) };

    info = vi.fn(async () => ({ version: { distribution: 'elasticsearch', number: '8.19.0' }, tagline: 'You Know, for Search' }));
  }
  class OpenClientStub {
    search = openSearchFn;

    ingest = { putPipeline: vi.fn(async () => ({ body: {} })) };

    info = vi.fn(async () => ({ body: { version: { distribution: 'opensearch', number: '3.9.0' }, tagline: 'The OpenSearch Project' } }));
  }
  return { elkSearch: elkSearchFn, openSearch: openSearchFn, FakeElkClient: ElkClientStub, FakeOpenClient: OpenClientStub };
});

vi.mock('@elastic/elasticsearch', () => ({ Client: FakeElkClient }));
vi.mock('@opensearch-project/opensearch', () => ({ Client: FakeOpenClient }));
vi.mock('@opensearch-project/opensearch/aws', () => ({ AwsSigv4Signer: vi.fn(() => ({})) }));

import conf from '../../../src/config/conf';
import { elRawSearch, searchEngineInit, toOpenSearchQuery } from '../../../src/database/engine';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

const EMPTY_RESULT = { hits: { hits: [] }, _shards: { failed: 0 } };
const SOURCE = { excludes: ['rel_*'], includes: ['internal_id', 'standard_id'] };

const initEngine = async (client: 'elasticsearch8' | 'opensearch') => {
  const realGet = conf.get.bind(conf);
  vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
    if (key === 'elasticsearch:engine_client') return client;
    return realGet(key as string);
  });
  await searchEngineInit();
};

describe('engine: _source filtering', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should move an { includes, excludes } _source to the body for OpenSearch', () => {
    const query = { index: 'opencti_*', size: 10, _source: SOURCE, body: { query: { match_all: {} } } };

    expect(toOpenSearchQuery(query)).toEqual({ index: 'opencti_*', size: 10, body: { query: { match_all: {} }, _source: SOURCE } });
  });

  it('should keep a _source the query string carries as is', () => {
    const disabled = { index: 'opencti_*', _source: false, body: {} };
    const fields = { index: 'opencti_*', _source: ['internal_id'], body: {} };
    const none = { index: 'opencti_*', body: {} };

    expect(toOpenSearchQuery(disabled)).toBe(disabled);
    expect(toOpenSearchQuery(fields)).toBe(fields);
    expect(toOpenSearchQuery(none)).toBe(none);
  });

  it('should send the _source filter in the body on OpenSearch', async () => {
    openSearch.mockResolvedValue({ body: EMPTY_RESULT });
    await initEngine('opensearch');

    await elRawSearch(testContext, ADMIN_USER, 'Malware', { index: 'opencti_*', _source: SOURCE, body: { query: { match_all: {} } } });

    const sent = openSearch.mock.calls[0][0];
    expect(sent._source).toBeUndefined();
    expect(sent.body._source).toEqual(SOURCE);
  });

  it('should leave the query unchanged on Elasticsearch', async () => {
    elkSearch.mockResolvedValue(EMPTY_RESULT);
    await initEngine('elasticsearch8');

    const query = { index: 'opencti_*', _source: SOURCE, body: { query: { match_all: {} } } };
    await elRawSearch(testContext, ADMIN_USER, 'Malware', query);

    expect(elkSearch).toHaveBeenCalledWith(query, expect.anything());
  });
});
