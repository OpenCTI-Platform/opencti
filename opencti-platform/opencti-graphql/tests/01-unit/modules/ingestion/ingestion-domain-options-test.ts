import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  getHttpClientMock,
  httpGetMock,
  httpRequestMock,
  decryptIngestionCredentialMock,
  findJsonMapperByIdMock,
  getEntitiesMapFromCacheMock,
  jsonMappingExecutionMock,
} = vi.hoisted(() => ({
  getHttpClientMock: vi.fn(),
  httpGetMock: vi.fn(),
  httpRequestMock: vi.fn(),
  decryptIngestionCredentialMock: vi.fn(),
  findJsonMapperByIdMock: vi.fn(),
  getEntitiesMapFromCacheMock: vi.fn(),
  jsonMappingExecutionMock: vi.fn(),
}));

vi.mock('../../../../src/utils/http-client', () => ({
  OpenCTIHeaders: class OpenCTIHeaders {},
  getHttpClient: getHttpClientMock,
}));

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (key: string) => {
        if (key === 'ingestion_manager:feed:request_timeout') return 7777;
        return actual.default.get(key);
      },
    },
  };
});

vi.mock('../../../../src/modules/ingestion/ingestion-common', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/modules/ingestion/ingestion-common')>();
  return {
    ...actual,
    decryptIngestionCredential: decryptIngestionCredentialMock,
  };
});

vi.mock('../../../../src/modules/internal/jsonMapper/jsonMapper-domain', () => ({
  findById: findJsonMapperByIdMock,
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesMapFromCache: getEntitiesMapFromCacheMock,
}));

vi.mock('../../../../src/parser/json-mapper', () => ({
  default: jsonMappingExecutionMock,
}));

import { fetchCsvFromUrl } from '../../../../src/modules/ingestion/ingestion-csv-domain';
import { executeJsonQuery } from '../../../../src/modules/ingestion/ingestion-json-domain';

describe('Ingestion domain timeout options', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    decryptIngestionCredentialMock.mockResolvedValue('');
    getHttpClientMock.mockReturnValue({
      get: httpGetMock,
      request: httpRequestMock,
    });
  });

  it('should pass timeout to csv http client options', async () => {
    httpGetMock.mockResolvedValue({
      data: Buffer.from('header\nvalue'),
      headers: {},
    });

    const csvMapper = { skipLineChar: '#' } as any;
    const ingestion = {
      uri: 'http://localhost/csv',
      authentication_type: 'none',
      ssl_verify: false,
    } as any;

    await fetchCsvFromUrl(csvMapper, ingestion, { timeout: 1234 });

    expect(getHttpClientMock).toHaveBeenCalledWith(
      expect.objectContaining({ timeout: 1234, responseType: 'arraybuffer' }),
    );
  });

  it('should fallback to configured timeout for csv when timeout option is omitted', async () => {
    httpGetMock.mockResolvedValue({
      data: Buffer.from('header\nvalue'),
      headers: {},
    });

    const csvMapper = { skipLineChar: '#' } as any;
    const ingestion = {
      uri: 'http://localhost/csv',
      authentication_type: 'none',
      ssl_verify: false,
    } as any;

    await fetchCsvFromUrl(csvMapper, ingestion);

    expect(getHttpClientMock).toHaveBeenCalledWith(
      expect.objectContaining({ timeout: 7777, responseType: 'arraybuffer' }),
    );
  });

  it('should pass timeout to json http client options', async () => {
    httpRequestMock.mockResolvedValueOnce({
      data: { items: [] },
      headers: {},
    });
    findJsonMapperByIdMock.mockResolvedValue({
      representations: '[]',
      variables: '[]',
    });
    getEntitiesMapFromCacheMock.mockResolvedValue(new Map());
    jsonMappingExecutionMock.mockResolvedValue([]);

    const ingestion = {
      headers: [],
      ingestion_json_state: null,
      query_attributes: [],
      authentication_type: 'none',
      ssl_verify: false,
      uri: 'http://localhost/json',
      body: '{}',
      verb: 'POST',
      json_mapper_id: 'json-mapper--1',
      user_id: null,
      pagination_with_sub_page: false,
      pagination_with_sub_page_attribute_path: null,
    } as any;

    await executeJsonQuery({} as any, ingestion, { timeout: 4321 });

    expect(getHttpClientMock).toHaveBeenCalledWith(
      expect.objectContaining({ timeout: 4321, responseType: 'json' }),
    );
  });

  it('should fallback to configured timeout for json when timeout option is omitted', async () => {
    httpRequestMock.mockResolvedValueOnce({
      data: { items: [] },
      headers: {},
    });
    findJsonMapperByIdMock.mockResolvedValue({
      representations: '[]',
      variables: '[]',
    });
    getEntitiesMapFromCacheMock.mockResolvedValue(new Map());
    jsonMappingExecutionMock.mockResolvedValue([]);

    const ingestion = {
      headers: [],
      ingestion_json_state: null,
      query_attributes: [],
      authentication_type: 'none',
      ssl_verify: false,
      uri: 'http://localhost/json',
      body: '{}',
      verb: 'POST',
      json_mapper_id: 'json-mapper--1',
      user_id: null,
      pagination_with_sub_page: false,
      pagination_with_sub_page_attribute_path: null,
    } as any;

    await executeJsonQuery({} as any, ingestion);

    expect(getHttpClientMock).toHaveBeenCalledWith(
      expect.objectContaining({ timeout: 7777, responseType: 'json' }),
    );
  });

  it('should verify the json feed certificate unless ssl_verify is explicitly false', async () => {
    httpRequestMock.mockResolvedValue({
      data: { items: [] },
      headers: {},
    });
    findJsonMapperByIdMock.mockResolvedValue({
      representations: '[]',
      variables: '[]',
    });
    getEntitiesMapFromCacheMock.mockResolvedValue(new Map());
    jsonMappingExecutionMock.mockResolvedValue([]);

    const ingestion = {
      headers: [],
      ingestion_json_state: null,
      query_attributes: [],
      authentication_type: 'none',
      uri: 'http://localhost/json',
      body: '{}',
      verb: 'POST',
      json_mapper_id: 'json-mapper--1',
      user_id: null,
      pagination_with_sub_page: false,
      pagination_with_sub_page_attribute_path: null,
    } as any;

    await executeJsonQuery({} as any, ingestion);
    await executeJsonQuery({} as any, { ...ingestion, ssl_verify: false });

    expect(getHttpClientMock).toHaveBeenNthCalledWith(1, expect.objectContaining({ rejectUnauthorized: true }));
    expect(getHttpClientMock).toHaveBeenNthCalledWith(2, expect.objectContaining({ rejectUnauthorized: false }));
  });
});

describe('Ingestion JSON feed destination', () => {
  const jsonIngestion = (overrides: Record<string, unknown> = {}) => ({
    headers: [{ name: 'X-Api-Key', value: 'header-secret' }, { name: 'X-Client', value: 'opencti' }],
    ingestion_json_state: null,
    query_attributes: [],
    authentication_type: 'bearer',
    authentication_value: 'encrypted',
    uri: 'https://api.example.com/feed',
    body: '',
    verb: 'GET',
    json_mapper_id: 'json-mapper--1',
    user_id: null,
    pagination_with_sub_page: false,
    pagination_with_sub_page_attribute_path: null,
    ...overrides,
  } as any);

  beforeEach(() => {
    vi.clearAllMocks();
    decryptIngestionCredentialMock.mockResolvedValue('bearer-secret');
    getHttpClientMock.mockReturnValue({ get: httpGetMock, request: httpRequestMock });
    findJsonMapperByIdMock.mockResolvedValue({ representations: '[]', variables: '[]' });
    getEntitiesMapFromCacheMock.mockResolvedValue(new Map());
    jsonMappingExecutionMock.mockResolvedValue([]);
  });

  it('refuses to send the credentials of the feed to another server than the one of its URI', async () => {
    const ingestion = jsonIngestion({
      uri: 'https://$h:x@api.example.com/feed',
      query_attributes: [{ type: 'data', from: 'h', to: 'h', default: 'evil.example.org/?', exposed: 'query_param' }],
    });
    await expect(executeJsonQuery({} as any, ingestion)).rejects.toThrow('The URI of the feed points to another server once its variables are replaced');
    expect(httpRequestMock).not.toHaveBeenCalled();
  });

  it('fetches a next page of another server without the credentials nor the sensitive headers of the feed', async () => {
    httpRequestMock
      .mockResolvedValueOnce({ data: { next: 'https://cdn.example.org/page-2' }, headers: {} })
      .mockResolvedValueOnce({ data: {}, headers: {} });
    const publicRequest = vi.fn().mockResolvedValue({ data: { next: 'https://api.example.com/page-3' }, headers: {} });
    getHttpClientMock
      .mockReturnValueOnce({ get: httpGetMock, request: httpRequestMock })
      .mockReturnValueOnce({ get: httpGetMock, request: publicRequest });
    const ingestion = jsonIngestion({ pagination_with_sub_page: true, pagination_with_sub_page_attribute_path: '$.next' });
    await executeJsonQuery({} as any, ingestion);
    const [[feedClient], [publicClient]] = getHttpClientMock.mock.calls;
    expect(feedClient.headers).toMatchObject({ Authorization: 'Bearer bearer-secret', 'X-Api-Key': 'header-secret' });
    expect(publicClient.headers).toEqual({ Accept: 'application/json', 'X-Client': 'opencti' });
    expect(publicClient.certificates).toBeUndefined();
    expect(publicRequest).toHaveBeenCalledWith(expect.objectContaining({ url: 'https://cdn.example.org/page-2' }));
    expect(httpRequestMock).toHaveBeenNthCalledWith(2, expect.objectContaining({ url: 'https://api.example.com/page-3' }));
    expect(httpRequestMock).toHaveBeenCalledTimes(2);
  });
});
