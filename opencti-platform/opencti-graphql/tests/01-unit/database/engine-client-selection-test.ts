import { beforeEach, describe, expect, it, vi } from 'vitest';

// The server every fake client answers for; each test sets it before calling searchEngineInit.
const { server, FakeElk8Client, FakeElk9Client, FakeOpenClient } = vi.hoisted(() => {
  const serverState = { distribution: 'elasticsearch', number: '8.19.0', tagline: 'You Know, for Search' };
  const serverInfo = () => ({ version: { distribution: serverState.distribution, number: serverState.number }, tagline: serverState.tagline });
  class Elk8ClientStub {
    ingest = { putPipeline: vi.fn(async () => ({})) };

    info = vi.fn(async () => serverInfo());
  }
  class Elk9ClientStub {
    ingest = { putPipeline: vi.fn(async () => ({})) };

    info = vi.fn(async () => serverInfo());
  }
  class OpenClientStub {
    ingest = { putPipeline: vi.fn(async () => ({ body: {} })) };

    info = vi.fn(async () => ({ body: serverInfo() }));
  }
  return { server: serverState, FakeElk8Client: Elk8ClientStub, FakeElk9Client: Elk9ClientStub, FakeOpenClient: OpenClientStub };
});

vi.mock('@elastic/elasticsearch', () => ({ Client: FakeElk8Client }));
vi.mock('@elastic/elasticsearch-v9', () => ({ Client: FakeElk9Client }));
vi.mock('@opensearch-project/opensearch', () => ({ Client: FakeOpenClient }));
vi.mock('@opensearch-project/opensearch/aws', () => ({ AwsSigv4Signer: vi.fn(() => ({})) }));

import conf, { logApp } from '../../../src/config/conf';
import { engine, isElkEngine, searchEngineInit } from '../../../src/database/engine';

const DEPRECATION_WARNING = expect.stringContaining('Elasticsearch 8.x server support is deprecated');

const initEngine = async (selector: 'elk' | 'opensearch' | 'auto', serverVersion: string, distribution = 'elasticsearch') => {
  server.number = serverVersion;
  server.distribution = distribution;
  server.tagline = distribution === 'opensearch' ? 'The OpenSearch Project: https://opensearch.org/' : 'You Know, for Search';
  const realGet = conf.get.bind(conf);
  vi.spyOn(conf, 'get').mockImplementation((key?: string) => {
    if (key === 'elasticsearch:engine_selector') return selector;
    return realGet(key as string);
  });
  await searchEngineInit();
};

describe('engine: Elasticsearch client selection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it.each(['elk', 'auto'] as const)('should use the 8.x client on an Elasticsearch 8 server (selector %s)', async (selector) => {
    const warn = vi.spyOn(logApp, 'warn');
    await initEngine(selector, '8.19.0');

    expect(engine).toBeInstanceOf(FakeElk8Client);
    expect(isElkEngine()).toBe(true);
    expect(warn).toHaveBeenCalledWith(DEPRECATION_WARNING);
  });

  it.each(['elk', 'auto'] as const)('should use the 9.x client on an Elasticsearch 9 server (selector %s)', async (selector) => {
    const warn = vi.spyOn(logApp, 'warn');
    await initEngine(selector, '9.1.0');

    expect(engine).toBeInstanceOf(FakeElk9Client);
    expect(isElkEngine()).toBe(true);
    expect(warn).not.toHaveBeenCalledWith(DEPRECATION_WARNING);
  });

  it.each(['opensearch', 'auto'] as const)('should keep the OpenSearch client on an OpenSearch server (selector %s)', async (selector) => {
    await initEngine(selector, '3.7.0', 'opensearch');

    expect(engine).toBeInstanceOf(FakeOpenClient);
    expect(isElkEngine()).toBe(false);
  });
});
