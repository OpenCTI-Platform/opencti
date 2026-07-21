import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import useDeployedIntegrations, { connectorIdFromIngestId } from './useDeployedIntegrations';

type HookProps = Parameters<typeof useDeployedIntegrations>[0];

const makeConnector = (overrides: Record<string, unknown> = {}) => ({
  id: 'connector-1',
  name: 'My Connector',
  title: null,
  connector_type: 'EXTERNAL_IMPORT',
  updated_at: '2026-01-01T00:00:00.000Z',
  is_managed: false,
  manager_contract_excerpt: null,
  ...overrides,
});

const makeState = (overrides: Record<string, unknown> = {}) => ({
  id: 'connector-1',
  active: true,
  manager_current_status: null,
  manager_requested_status: null,
  ...overrides,
});

const emptyFeeds = {
  synchronizers: { pageInfo: { globalCount: 0 }, edges: [] },
  ingestionRsss: { pageInfo: { globalCount: 0 }, edges: [] },
  ingestionTaxiis: { pageInfo: { globalCount: 0 }, edges: [] },
  ingestionTaxiiCollections: { pageInfo: { globalCount: 0 }, edges: [] },
  ingestionCsvs: { pageInfo: { globalCount: 0 }, edges: [] },
  ingestionJsons: { pageInfo: { globalCount: 0 }, edges: [] },
};

const renderIntegrations = ({
  connectors = [],
  states = [],
  queues = [],
  feeds = {},
  forms = [],
  logosBySlug = new Map<string, string>(),
}: {
  connectors?: unknown[];
  states?: unknown[];
  queues?: { name: string; messages: unknown }[];
  feeds?: Record<string, unknown>;
  forms?: unknown[];
  logosBySlug?: Map<string, string>;
} = {}) => {
  const props = {
    connectorsListData: { connectors },
    connectorsStateData: { connectors: states, rabbitMQMetrics: { queues } },
    feedsData: { ...emptyFeeds, ...feeds },
    formsData: { forms: { pageInfo: { globalCount: forms.length }, edges: forms.map((node) => ({ node })) } },
    logosBySlug,
  } as unknown as HookProps;
  return renderHook(() => useDeployedIntegrations(props));
};

describe('useDeployedIntegrations', () => {
  it('returns an empty list when every data source is empty or missing', () => {
    const { result: withEmptyData } = renderIntegrations();
    expect(withEmptyData.current).toEqual([]);
    const { result: withNullData } = renderHook(() => useDeployedIntegrations({
      connectorsListData: null,
      connectorsStateData: null,
      feedsData: null,
      formsData: null,
      logosBySlug: new Map(),
    }));
    expect(withNullData.current).toEqual([]);
  });

  describe('registered connectors', () => {
    it('maps a connector with its live state and logo', () => {
      const { result } = renderIntegrations({
        connectors: [makeConnector({ manager_contract_excerpt: { slug: 'my-connector', title: 'Contract title' } })],
        states: [makeState({ active: true })],
        logosBySlug: new Map([['my-connector', 'data:image/png;base64,logo']]),
      });
      expect(result.current).toHaveLength(1);
      const item = result.current[0];
      expect(item.kind).toBe('connector');
      expect(item.sectionKey).toBe('EXTERNAL_IMPORT');
      expect(item.name).toBe('My Connector');
      expect(item.description).toBe('Contract title');
      expect(item.logo).toBe('data:image/png;base64,logo');
      expect(item.status).toBe('active');
      expect(item.detailUrl).toBe('/dashboard/integrations/connectors/connector-1');
      expect(item.searchText).toBe('my connector external_import');
      expect(item.connector?.active).toBe(true);
    });

    it('prefers the connector title over its technical name', () => {
      const { result } = renderIntegrations({
        connectors: [makeConnector({ title: 'Nice title' })],
      });
      expect(result.current[0].name).toBe('Nice title');
    });

    it('skips internal connectors', () => {
      const { result } = renderIntegrations({
        connectors: [makeConnector({ id: 'internal-1', connector_type: 'internal' }), makeConnector()],
      });
      expect(result.current.map((item) => item.id)).toEqual(['connector-1']);
    });

    it('reports an inactive status when the connector state is inactive', () => {
      const { result } = renderIntegrations({
        connectors: [makeConnector()],
        states: [makeState({ active: false })],
      });
      expect(result.current[0].status).toBe('inactive');
    });

    it('reports a processing status while a managed connector is transitioning', () => {
      const { result } = renderIntegrations({
        connectors: [makeConnector()],
        states: [makeState({ manager_current_status: 'stopped', manager_requested_status: 'starting' })],
      });
      expect(result.current[0].status).toBe('processing');
      expect(result.current[0].statusLabel).toBe('starting');
    });

    it('sums push and listen queue messages per connector', () => {
      const { result } = renderIntegrations({
        connectors: [makeConnector()],
        queues: [
          { name: 'push_connector-1', messages: '3' },
          { name: 'listen_connector-1', messages: 4 },
          { name: 'push_other-connector', messages: 100 },
          { name: 'unrelated-queue', messages: 50 },
          { name: 'push_connector-1-bis', messages: 'not-a-number' },
        ],
      });
      expect(result.current[0].messagesCount).toBe(7);
    });
  });

  describe('feed twin connectors', () => {
    it('folds the technical twin connector into its feed entry and surfaces its queue metrics', () => {
      const feedId = 'rss-feed-1';
      const twinId = connectorIdFromIngestId(feedId);
      const { result } = renderIntegrations({
        connectors: [
          makeConnector({ id: twinId, name: 'RSS twin connector' }),
          makeConnector(),
        ],
        queues: [{ name: `push_${twinId}`, messages: 12 }],
        feeds: {
          ingestionRsss: {
            pageInfo: { globalCount: 1 },
            edges: [{ node: { id: feedId, name: 'My RSS feed', description: null, uri: 'https://feed', ingestion_running: true } }],
          },
        },
      });
      // The twin is not listed as a connector card: one connector + one feed.
      expect(result.current.map((item) => item.id).sort()).toEqual(['connector-1', feedId].sort());
      const feed = result.current.find((item) => item.id === feedId)!;
      expect(feed.kind).toBe('rss');
      expect(feed.messagesCount).toBe(12);
    });
  });

  describe('built-in feed instances', () => {
    it('maps synchronizers with their own queue metrics and state date', () => {
      const { result } = renderIntegrations({
        feeds: {
          synchronizers: {
            pageInfo: { globalCount: 1 },
            edges: [{
              node: {
                id: 'sync-1',
                name: 'Remote stream',
                uri: 'https://remote',
                running: true,
                current_state_date: '2026-02-01T00:00:00.000Z',
                queue_messages: 5,
                user: { name: 'admin' },
              },
            }],
          },
        },
      });
      expect(result.current).toHaveLength(1);
      const item = result.current[0];
      expect(item.kind).toBe('sync');
      expect(item.status).toBe('active');
      expect(item.messagesCount).toBe(5);
      expect(item.lastRunDate).toBe('2026-02-01T00:00:00.000Z');
      expect(item.userName).toBe('admin');
      expect(item.detailUrl).toBe('/dashboard/integrations/feeds/sync/sync-1');
    });

    it('maps every feed kind to its section and detail url', () => {
      const makeFeedNode = (id: string) => ({
        node: { id, name: id, description: null, uri: null, ingestion_running: false, last_execution_date: null, updated_at: null, user: null },
      });
      const { result } = renderIntegrations({
        feeds: {
          ingestionRsss: { pageInfo: { globalCount: 1 }, edges: [makeFeedNode('rss-1')] },
          ingestionTaxiis: { pageInfo: { globalCount: 1 }, edges: [makeFeedNode('taxii-1')] },
          ingestionTaxiiCollections: { pageInfo: { globalCount: 1 }, edges: [makeFeedNode('taxii-push-1')] },
          ingestionCsvs: { pageInfo: { globalCount: 1 }, edges: [makeFeedNode('csv-1')] },
          ingestionJsons: { pageInfo: { globalCount: 1 }, edges: [makeFeedNode('json-1')] },
        },
      });
      const byId = new Map(result.current.map((item) => [item.id, item]));
      expect(byId.get('rss-1')?.kind).toBe('rss');
      expect(byId.get('taxii-1')?.kind).toBe('taxii');
      expect(byId.get('taxii-push-1')?.kind).toBe('taxii-push');
      expect(byId.get('csv-1')?.kind).toBe('csv');
      expect(byId.get('json-1')?.kind).toBe('json');
      for (const item of result.current) {
        expect(item.sectionKey).toBe(item.kind);
        expect(item.detailUrl).toBe(`/dashboard/integrations/feeds/${item.kind}/${item.id}`);
        expect(item.status).toBe('inactive');
      }
    });

    it('maps form intakes with their active flag', () => {
      const { result } = renderIntegrations({
        forms: [{ id: 'form-1', name: 'Intake form', description: 'desc', active: true, updated_at: '2026-03-01T00:00:00.000Z' }],
      });
      expect(result.current).toHaveLength(1);
      const item = result.current[0];
      expect(item.kind).toBe('form');
      expect(item.status).toBe('active');
      expect(item.running).toBe(true);
      expect(item.updatedAt).toBe('2026-03-01T00:00:00.000Z');
      expect(item.detailUrl).toBe('/dashboard/integrations/feeds/form/form-1');
    });
  });
});
