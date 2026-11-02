import { beforeEach, describe, expect, it, vi } from 'vitest';

// Fake clients, and the answer of GET / that each test sets before calling searchEngineInit.
// `info` is the GET / of the reachability check, run when the client is not detected (forced or AWS).
const { probe, info, FakeElk8Client, FakeElk9Client, FakeOpenClient } = vi.hoisted(() => {
  const infoStub = vi.fn(async () => ({}));
  class Elk8ClientStub {
    info = infoStub;
    ingest = { putPipeline: vi.fn(async () => ({})) };
  }
  class Elk9ClientStub {
    info = infoStub;
    ingest = { putPipeline: vi.fn(async () => ({})) };
  }
  class OpenClientStub {
    info = infoStub;
    ingest = { putPipeline: vi.fn(async () => ({ body: {} })) };
  }
  return { probe: vi.fn(), info: infoStub, FakeElk8Client: Elk8ClientStub, FakeElk9Client: Elk9ClientStub, FakeOpenClient: OpenClientStub };
});

vi.mock('@elastic/elasticsearch', () => ({ Client: FakeElk8Client }));
vi.mock('@elastic/elasticsearch-v9', () => ({ Client: FakeElk9Client }));
vi.mock('@opensearch-project/opensearch', () => ({ Client: FakeOpenClient }));
vi.mock('@opensearch-project/opensearch/aws', () => ({ AwsSigv4Signer: vi.fn(() => ({})) }));
// Only the network call is replaced: the decision rules run for real
vi.mock('../../../src/database/engine-detection', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/engine-detection')>()),
  probeEngine: probe,
}));

import conf, { logApp } from '../../../src/config/conf';
import { engine, isElkEngine, isRuntimeSortEnable, searchEngineInit } from '../../../src/database/engine';

const DEPRECATION_WARNING = expect.stringContaining('Elasticsearch versions before 9 are deprecated');
const ES8 = { version: { number: '8.19.0', build_flavor: 'default' }, tagline: 'You Know, for Search' };
const ES9 = { version: { number: '9.1.0', build_flavor: 'default' }, tagline: 'You Know, for Search' };
const OPENSEARCH = { version: { distribution: 'opensearch', number: '3.7.0' }, tagline: 'The OpenSearch Project: https://opensearch.org/' };

const initEngine = async (settings: Record<string, unknown>) => {
  const realGet = conf.get.bind(conf);
  vi.spyOn(conf, 'get').mockImplementation((key?: string) => (key && key in settings ? settings[key] : realGet(key as string)));
  await searchEngineInit();
};

describe('engine: search engine client selection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should detect Elasticsearch 8 and use the 8.x client, with the deprecation warning', async () => {
    probe.mockResolvedValue(ES8);
    const warn = vi.spyOn(logApp, 'warn');
    await initEngine({ 'elasticsearch:engine_client': 'auto' });

    expect(engine).toBeInstanceOf(FakeElk8Client);
    expect(isElkEngine()).toBe(true);
    expect(isRuntimeSortEnable()).toBe(true);
    expect(warn).toHaveBeenCalledWith(DEPRECATION_WARNING);
  });

  it('should detect Elasticsearch 9 and use the 9.x client, without the deprecation warning', async () => {
    probe.mockResolvedValue(ES9);
    const warn = vi.spyOn(logApp, 'warn');
    await initEngine({ 'elasticsearch:engine_client': 'auto' });

    expect(engine).toBeInstanceOf(FakeElk9Client);
    expect(isElkEngine()).toBe(true);
    expect(warn).not.toHaveBeenCalledWith(DEPRECATION_WARNING);
  });

  it('should detect OpenSearch and use the OpenSearch client', async () => {
    probe.mockResolvedValue(OPENSEARCH);
    await initEngine({ 'elasticsearch:engine_client': 'auto' });

    expect(engine).toBeInstanceOf(FakeOpenClient);
    expect(isElkEngine()).toBe(false);
    expect(isRuntimeSortEnable()).toBe(false);
  });

  it.each([
    ['elasticsearch8', FakeElk8Client, true],
    ['elasticsearch9', FakeElk9Client, true],
    ['opensearch', FakeOpenClient, false],
  ] as const)('should trust a forced %s client without reading the server', async (client, expectedClass, isElk) => {
    const warn = vi.spyOn(logApp, 'warn');
    await initEngine({ 'elasticsearch:engine_client': client });

    expect(probe).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledOnce();
    expect(engine).toBeInstanceOf(expectedClass);
    expect(isElkEngine()).toBe(isElk);
    expect(warn).not.toHaveBeenCalledWith(DEPRECATION_WARNING);
  });

  it('should stop when a forced client finds no engine', async () => {
    info.mockRejectedValueOnce(new Error('connect ECONNREFUSED'));
    await expect(initEngine({ 'elasticsearch:engine_client': 'elasticsearch9' })).rejects.toThrow('Search engine seems down');
  });

  it('should start a forced client when the engine refuses GET /', async () => {
    info.mockRejectedValueOnce(Object.assign(new Error('security_exception'), { meta: { statusCode: 403 } }));
    await initEngine({ 'elasticsearch:engine_client': 'elasticsearch9' });

    expect(engine).toBeInstanceOf(FakeElk9Client);
  });

  it('should refuse an unknown forced client', async () => {
    await expect(initEngine({ 'elasticsearch:engine_client': 'elasticsearch10' })).rejects.toThrow('Invalid elasticsearch:engine_client');
  });

  it('should use the OpenSearch client with AWS SigV4, without reading the server', async () => {
    await initEngine({ 'elasticsearch:engine_client': 'auto', 'opensearch:region': 'eu-west-1' });

    expect(probe).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledOnce();
    expect(engine).toBeInstanceOf(FakeOpenClient);
  });

  it('should stop when the AWS OpenSearch engine does not answer', async () => {
    info.mockRejectedValueOnce(new Error('connect ETIMEDOUT'));
    await expect(initEngine({ 'elasticsearch:engine_client': 'auto', 'opensearch:region': 'eu-west-1' })).rejects.toThrow('Search engine seems down');
  });

  it('should refuse a forced Elasticsearch client with AWS SigV4', async () => {
    await expect(initEngine({ 'elasticsearch:engine_client': 'elasticsearch9', 'opensearch:region': 'eu-west-1' }))
      .rejects.toThrow('must be opensearch with AWS SigV4');
  });

  it('should stop when the server cannot be read', async () => {
    probe.mockRejectedValue(new Error('Search engine seems down'));
    await expect(initEngine({ 'elasticsearch:engine_client': 'auto' })).rejects.toThrow('Search engine seems down');
  });

  it('should warn that the former settings are ignored', async () => {
    probe.mockResolvedValue(ES9);
    const warn = vi.spyOn(logApp, 'warn');
    await initEngine({ 'elasticsearch:engine_client': 'auto', 'elasticsearch:engine_selector': 'elk', 'elasticsearch:engine_check': true });

    expect(warn).toHaveBeenCalledWith(expect.stringContaining('elasticsearch:engine_selector and elasticsearch:engine_check no longer apply'));
    expect(engine).toBeInstanceOf(FakeElk9Client);
  });
});
