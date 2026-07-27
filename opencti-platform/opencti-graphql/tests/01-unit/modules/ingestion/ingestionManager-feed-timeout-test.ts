import { AxiosError } from 'axios';
import TurndownService from 'turndown';
import { describe, expect, it, vi, beforeEach } from 'vitest';

const findAllRssIngestionMock = vi.fn();
const patchRssIngestionMock = vi.fn();
const findAllTaxiiIngestionMock = vi.fn();
const patchTaxiiIngestionMock = vi.fn();
const findAllCsvIngestionMock = vi.fn();
const patchCsvIngestionMock = vi.fn();
const fetchCsvFromUrlMock = vi.fn();
const findAllJsonIngestionMock = vi.fn();
const patchJsonIngestionMock = vi.fn();
const executeJsonQueryMock = vi.fn();
const decryptIngestionCredentialMock = vi.fn();
const queueDetailsMock = vi.fn();
const getHttpClientMock = vi.fn();

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (key: string) => {
        if (key === 'ingestion_manager:feed:request_timeout') return 50;
        return actual.default.get(key);
      },
    },
    booleanConf: () => false,
    logApp: {
      ...actual.logApp,
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
  };
});

vi.mock('../../../../src/modules/ingestion/ingestion-rss-domain', () => ({
  findAllRssIngestion: findAllRssIngestionMock,
  patchRssIngestion: patchRssIngestionMock,
}));

vi.mock('../../../../src/modules/ingestion/ingestion-taxii-domain', () => ({
  findAllTaxiiIngestion: findAllTaxiiIngestionMock,
  patchTaxiiIngestion: patchTaxiiIngestionMock,
}));

vi.mock('../../../../src/modules/ingestion/ingestion-csv-domain', () => ({
  findAllCsvIngestion: findAllCsvIngestionMock,
  patchCsvIngestion: patchCsvIngestionMock,
  fetchCsvFromUrl: fetchCsvFromUrlMock,
}));

vi.mock('../../../../src/modules/ingestion/ingestion-json-domain', () => ({
  findAllJsonIngestion: findAllJsonIngestionMock,
  patchJsonIngestion: patchJsonIngestionMock,
  executeJsonQuery: executeJsonQueryMock,
}));

vi.mock('../../../../src/modules/ingestion/ingestion-common', () => ({
  decryptIngestionCredential: decryptIngestionCredentialMock,
}));

vi.mock('../../../../src/domain/connector', () => ({
  queueDetails: queueDetailsMock,
  connectorIdFromIngestId: (id: string) => `connector-${id}`,
}));

vi.mock('../../../../src/manager/ingestionManager/ingestionManagerPushToQueue', () => ({
  pushBundleToConnectorQueue: vi.fn(),
  updateBuiltInConnectorInfo: vi.fn(),
}));

vi.mock('../../../../src/utils/http-client', () => ({
  OpenCTIHeaders: class OpenCTIHeaders {},
  getHttpClient: getHttpClientMock,
}));

const timeoutError = new AxiosError('timeout', 'ECONNABORTED');
const validRss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test feed</title>
    <pubDate>Wed, 10 Jul 2024 12:00:00 GMT</pubDate>
    <item>
      <title>A working item</title>
      <link>http://localhost/items/1</link>
      <description>description</description>
      <pubDate>Wed, 10 Jul 2024 12:00:00 GMT</pubDate>
      <category>test</category>
    </item>
  </channel>
</rss>`;

describe('Ingestion manager feed timeout behavior', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    queueDetailsMock.mockResolvedValue({ messages_number: 0, messages_size: 0 });
    patchRssIngestionMock.mockResolvedValue({});
    patchTaxiiIngestionMock.mockResolvedValue({ current_state_cursor: undefined, added_after_start: undefined });
    patchCsvIngestionMock.mockResolvedValue({});
    patchJsonIngestionMock.mockResolvedValue({});
    decryptIngestionCredentialMock.mockResolvedValue('');
    fetchCsvFromUrlMock.mockRejectedValue(timeoutError);
    executeJsonQueryMock.mockResolvedValue({ objects: [], variables: {}, nextExecutionState: {} });

    getHttpClientMock.mockImplementation(() => ({
      get: async (uri: string) => {
        if (uri.includes('hang')) {
          throw timeoutError;
        }
        if (uri.includes('/collections/')) {
          return {
            data: { objects: [], more: false, next: undefined },
            headers: {},
            status: 200,
          };
        }
        return { data: validRss };
      },
    }));
  });

  it('should continue RSS iteration when one feed times out and another is healthy', async () => {
    const baseIngestion = {
      scheduling_period: 'auto',
      last_execution_date: undefined,
      ssl_verify: false,
      created_by_ref: 'identity--1',
      object_marking_refs: [],
      report_types: ['threat-report'],
    };

    const hangingIngestion = {
      ...baseIngestion,
      id: 'ingestion--hang',
      internal_id: 'internal--hang',
      name: 'Hanging RSS',
      uri: 'http://localhost/hang',
    };

    const healthyIngestion = {
      ...baseIngestion,
      id: 'ingestion--ok',
      internal_id: 'internal--ok',
      name: 'Working RSS',
      uri: 'http://localhost/feed',
      user_id: 'user--2',
    };

    findAllRssIngestionMock.mockResolvedValue([hangingIngestion, healthyIngestion]);

    const { rssExecutor } = await import('../../../../src/manager/ingestionManager');

    // The executor should still resolve: a timeout on one feed must not stop the whole RSS iteration.
    await expect(rssExecutor({} as any, new TurndownService())).resolves.toBeDefined();

    expect(patchRssIngestionMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'internal--hang',
      expect.objectContaining({ last_execution_date: expect.any(String) }),
    );

    expect(getHttpClientMock).toHaveBeenCalledWith(
      expect.objectContaining({ timeout: 50 }),
    );
  });

  it('should continue TAXII iteration when one feed times out and another is healthy', async () => {
    const baseIngestion = {
      scheduling_period: 'auto',
      last_execution_date: undefined,
      ssl_verify: false,
      version: 'v21',
      collection: 'default',
      authentication_type: 'none',
      authentication_value: undefined,
    };
    const hangingIngestion = {
      ...baseIngestion,
      id: 'taxii--hang',
      internal_id: 'taxii-internal--hang',
      name: 'Hanging TAXII',
      uri: 'http://localhost/hang',
      user_id: 'user--1',
    };
    const healthyIngestion = {
      ...baseIngestion,
      id: 'taxii--ok',
      internal_id: 'taxii-internal--ok',
      name: 'Working TAXII',
      uri: 'http://localhost/taxii',
      user_id: 'user--2',
    };
    findAllTaxiiIngestionMock.mockResolvedValue([hangingIngestion, healthyIngestion]);

    const { taxiiExecutor } = await import('../../../../src/manager/ingestionManager');

    await expect(taxiiExecutor({} as any)).resolves.toBeDefined();

    expect(patchTaxiiIngestionMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'taxii-internal--ok',
      expect.objectContaining({ last_execution_date: expect.any(String) }),
    );
    expect(getHttpClientMock).toHaveBeenCalledWith(
      expect.objectContaining({ timeout: 50 }),
    );
  });

  it('should catch CSV timeout and update last execution date', async () => {
    const csvIngestion = {
      id: 'csv--hang',
      internal_id: 'csv-internal--hang',
      name: 'Hanging CSV',
      user_id: 'user--1',
      scheduling_period: 'auto',
      last_execution_date: undefined,
      csv_mapper_type: 'inline',
      csv_mapper: '{}',
      markings: [],
    };
    findAllCsvIngestionMock.mockResolvedValue([csvIngestion]);

    const { csvExecutor } = await import('../../../../src/manager/ingestionManager');

    await expect(csvExecutor({} as any)).resolves.toBeDefined();

    expect(fetchCsvFromUrlMock).toHaveBeenCalledWith(
      expect.anything(),
      csvIngestion,
      expect.objectContaining({ timeout: 50 }),
    );
    expect(patchCsvIngestionMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'csv-internal--hang',
      expect.objectContaining({ last_execution_date: expect.any(String) }),
    );
  });

  it('should pass timeout to JSON query execution', async () => {
    const jsonIngestion = {
      id: 'json--ok',
      internal_id: 'json-internal--ok',
      name: 'Working JSON',
      user_id: 'user--1',
      scheduling_period: 'auto',
      last_execution_date: undefined,
      query_attributes: [],
    };
    findAllJsonIngestionMock.mockResolvedValue([jsonIngestion]);

    const { jsonExecutor } = await import('../../../../src/manager/ingestionManager');

    await expect(jsonExecutor({} as any)).resolves.toBeUndefined();

    expect(executeJsonQueryMock).toHaveBeenCalledWith(
      expect.anything(),
      jsonIngestion,
      expect.objectContaining({ timeout: 50 }),
    );
  });
});
