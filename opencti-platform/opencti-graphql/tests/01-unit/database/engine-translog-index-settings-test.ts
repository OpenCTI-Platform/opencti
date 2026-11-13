import { beforeEach, describe, expect, it, vi } from 'vitest';

// Fake clients capturing what the start-up refresh sends: the templates it rewrites and the settings
// it puts on every existing index. The Elasticsearch client answers the payload, OpenSearch wraps it.
const { capture, enabledFeatures, FakeElkClient, FakeOpenClient } = vi.hoisted(() => {
  const templateName = 'opencti_history';
  const indexName = 'opencti_history-000001';
  const captured = { templates: [] as any[], settings: [] as any[] };
  const features = { flags: [] as string[] };
  const clientOf = (wrap: (value: any) => any, rolloverSetting: any) => ({
    info: vi.fn(async () => wrap({})),
    ingest: { putPipeline: vi.fn(async () => wrap({})) },
    cluster: { putComponentTemplate: vi.fn(async () => wrap({})) },
    cat: {
      templates: vi.fn(async () => wrap([{ name: templateName }])),
      indices: vi.fn(async () => wrap([{ index: indexName }])),
    },
    indices: {
      putIndexTemplate: vi.fn(async (args: any) => {
        captured.templates.push(args);
        return wrap({});
      }),
      putSettings: vi.fn(async (args: any) => {
        captured.settings.push(args);
        return wrap({});
      }),
      putMapping: vi.fn(async () => wrap({})),
      getMapping: vi.fn(async () => wrap({ [indexName]: { mappings: { properties: {} } } })),
      getSettings: vi.fn(async () => wrap({ [indexName]: { settings: { index: rolloverSetting } } })),
    },
  });
  class ElkClientStub {
    constructor() {
      Object.assign(this, clientOf((value) => value, { lifecycle: { rollover_alias: templateName } }));
    }
  }
  class OpenClientStub {
    constructor() {
      Object.assign(this, clientOf((value) => ({ body: value }), { plugins: { index_state_management: { rollover_alias: templateName } } }));
    }
  }
  return { capture: captured, enabledFeatures: features, FakeElkClient: ElkClientStub, FakeOpenClient: OpenClientStub };
});

vi.mock('@elastic/elasticsearch', () => ({ Client: FakeElkClient }));
vi.mock('@elastic/elasticsearch-v9', () => ({ Client: FakeElkClient }));
vi.mock('@opensearch-project/opensearch', () => ({ Client: FakeOpenClient }));
vi.mock('@opensearch-project/opensearch/aws', () => ({ AwsSigv4Signer: vi.fn(() => ({})) }));
vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn((feature: string) => enabledFeatures.flags.includes(feature)),
}));

import conf, { logApp } from '../../../src/config/conf';
import { elUpdateIndicesMappings, searchEngineInit } from '../../../src/database/engine';

// One platform start: the engine client is forced, then the templates and the existing indices are refreshed
const startAndRefresh = async (client: string, flags: string[]) => {
  enabledFeatures.flags = flags;
  capture.templates = [];
  capture.settings = [];
  const realGet = conf.get.bind(conf);
  vi.spyOn(conf, 'get').mockImplementation((key?: string) => (key === 'elasticsearch:engine_client' ? client : realGet(key as string)));
  await searchEngineInit();
  await elUpdateIndicesMappings();
};

const templateDurability = () => capture.templates.map((args) => args.body.template.settings.index?.translog?.durability);
const indexDurability = () => capture.settings.map((args) => args.body.index?.translog?.durability);

describe('engine: translog durability sent to the search engine', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should write async on the templates and the existing indices by default', async () => {
    await startAndRefresh('elasticsearch9', []);

    expect(templateDurability()).toEqual(['async']);
    expect(indexDurability()).toEqual(['async']);
  });

  it('should write the Elasticsearch default on the templates and the existing indices with the opt-out flag', async () => {
    await startAndRefresh('elasticsearch9', ['ES_TRANSLOG_REQUEST']);

    expect(templateDurability()).toEqual(['request']);
    expect(indexDurability()).toEqual(['request']);
  });

  it('should never send a translog setting to OpenSearch, and warn that the opt-out flag is ignored', async () => {
    const warn = vi.spyOn(logApp, 'warn');
    await startAndRefresh('opensearch', ['ES_TRANSLOG_REQUEST']);

    expect(capture.templates.length).toBe(1);
    expect(capture.settings.length).toBe(1);
    expect(JSON.stringify(capture.templates)).not.toContain('translog');
    expect(JSON.stringify(capture.settings)).not.toContain('translog');
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('ES_TRANSLOG_REQUEST only applies to Elasticsearch'));
  });
});
