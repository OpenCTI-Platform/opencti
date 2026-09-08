import { beforeEach, describe, expect, it, vi } from 'vitest';

const { elkStats, openStats, FakeElkClient, FakeOpenClient } = vi.hoisted(() => {
  const elkStatsFn = vi.fn();
  const openStatsFn = vi.fn();
  class ElkClientStub {
    indices = { stats: elkStatsFn };

    ingest = { putPipeline: vi.fn(async () => ({})) };

    info = vi.fn(async () => ({ version: { distribution: 'elasticsearch', number: '8.19.0' }, tagline: 'You Know, for Search' }));
  }
  class OpenClientStub {
    indices = { stats: openStatsFn };

    ingest = { putPipeline: vi.fn(async () => ({ body: {} })) };

    info = vi.fn(async () => ({ body: { version: { distribution: 'opensearch', number: '2.11.0' }, tagline: 'The OpenSearch Project' } }));
  }
  return { elkStats: elkStatsFn, openStats: openStatsFn, FakeElkClient: ElkClientStub, FakeOpenClient: OpenClientStub };
});

vi.mock('@elastic/elasticsearch', () => ({ Client: FakeElkClient }));
vi.mock('@opensearch-project/opensearch', () => ({ Client: FakeOpenClient }));
vi.mock('@opensearch-project/opensearch/aws', () => ({ AwsSigv4Signer: vi.fn(() => ({})) }));

import conf from '../../../src/config/conf';
import { getEngineUsedSize, searchEngineInit } from '../../../src/database/engine';

const initEngine = async (selector: 'elk' | 'opensearch') => {
  const realGet = conf.get.bind(conf);
  vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
    if (key === 'elasticsearch:engine_selector') return selector;
    if (key === 'elasticsearch:engine_check') return false;
    return realGet(key as string);
  });
  await searchEngineInit();
};

describe('engine: getEngineUsedSize', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should return the primary store size reported by ElasticSearch', async () => {
    elkStats.mockResolvedValue({ _all: { primaries: { store: { size_in_bytes: 123456 } } } });
    await initEngine('elk');

    const result = await getEngineUsedSize();

    expect(result).toBe(123456);
  });

  it('should request the store metric as an array on ElasticSearch', async () => {
    elkStats.mockResolvedValue({ _all: { primaries: { store: { size_in_bytes: 1 } } } });
    await initEngine('elk');

    await getEngineUsedSize();

    expect(elkStats).toHaveBeenCalledWith(expect.objectContaining({ index: '*', metric: ['store'], expand_wildcards: 'all' }));
  });

  it('should return the primary store size reported by OpenSearch', async () => {
    openStats.mockResolvedValue({ body: { _all: { primaries: { store: { size_in_bytes: 654321 } } } } });
    await initEngine('opensearch');

    const result = await getEngineUsedSize();

    expect(result).toBe(654321);
  });

  it('should request the store metric as a string on OpenSearch', async () => {
    openStats.mockResolvedValue({ body: { _all: { primaries: { store: { size_in_bytes: 1 } } } } });
    await initEngine('opensearch');

    await getEngineUsedSize();

    expect(openStats).toHaveBeenCalledWith(expect.objectContaining({ index: '*', metric: 'store', expand_wildcards: 'all' }));
  });

  it('should return 0 when the engine reports no store size', async () => {
    elkStats.mockResolvedValue({ _all: { primaries: {} } });
    await initEngine('elk');

    const result = await getEngineUsedSize();

    expect(result).toBe(0);
  });

  it('should return 0 when the stats payload is empty', async () => {
    elkStats.mockResolvedValue({});
    await initEngine('elk');

    const result = await getEngineUsedSize();

    expect(result).toBe(0);
  });
});
