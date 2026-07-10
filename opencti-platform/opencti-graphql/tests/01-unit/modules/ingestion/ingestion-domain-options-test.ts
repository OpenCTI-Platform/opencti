import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  getHttpClientMock,
  httpGetMock,
  httpCallMock,
  decryptIngestionCredentialMock,
  findJsonMapperByIdMock,
  getEntitiesMapFromCacheMock,
  jsonMappingExecutionMock,
} = vi.hoisted(() => ({
  getHttpClientMock: vi.fn(),
  httpGetMock: vi.fn(),
  httpCallMock: vi.fn(),
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
      call: httpCallMock,
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
    httpCallMock.mockResolvedValueOnce({
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
    httpCallMock.mockResolvedValueOnce({
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
});
