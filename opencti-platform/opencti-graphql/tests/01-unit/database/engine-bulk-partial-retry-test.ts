import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const testMocks = vi.hoisted(() => ({
  bulk: vi.fn(),
  info: vi.fn(),
  putPipeline: vi.fn(),
  confGet: vi.fn(),
}));

vi.mock('@elastic/elasticsearch', () => {
  class MockElkClient {
    public ingest = { putPipeline: testMocks.putPipeline };

    public info = testMocks.info;

    public bulk = testMocks.bulk;

    // eslint-disable-next-line no-useless-constructor
    constructor(_config: unknown) {}
  }
  return { Client: MockElkClient };
});

vi.mock('@opensearch-project/opensearch', () => {
  class MockOpenClient {
    // eslint-disable-next-line no-useless-constructor
    constructor(_config: unknown) {}
  }
  return { Client: MockOpenClient };
});

vi.mock('@opensearch-project/opensearch/aws', () => ({
  AwsSigv4Signer: vi.fn().mockReturnValue({}),
}));

vi.mock('../../../src/config/credentials', () => ({
  enrichWithRemoteCredentials: vi.fn(async (_provider, auth) => auth),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  const confGet = vi.fn((key: string) => {
    if (key === 'elasticsearch:engine_selector') {
      return 'elk';
    }
    if (key === 'elasticsearch:engine_check') {
      return false;
    }
    return actual.default.get(key);
  });
  testMocks.confGet.mockImplementation(confGet);
  return {
    ...actual,
    default: { ...actual.default, get: confGet },
    booleanConf: vi.fn((key: string, defaultValue: boolean) => {
      if (key === 'elasticsearch:engine_check') {
        return false;
      }
      return defaultValue;
    }),
    extendedErrors: vi.fn(() => ({})),
    loadCert: vi.fn(() => null),
    logApp: {
      info: vi.fn(),
      warn: vi.fn(),
      debug: vi.fn(),
      error: vi.fn(),
    },
    logMigration: {
      info: vi.fn(),
      error: vi.fn(),
    },
  };
});

import { logApp } from '../../../src/config/conf';
import { elBulk, searchEngineInit } from '../../../src/database/engine';

const MAX_ATTEMPTS = 6; // 1 initial + BULK_MAX_RETRIES

const indexOp = (id: string) => [{ index: { _index: 'test-index', _id: id } }, { value: id }];
const updateOp = (id: string) => [{ update: { _index: 'test-index', _id: id } }, { script: { source: 'noop' } }];
const deleteOp = (id: string) => [{ delete: { _index: 'test-index', _id: id } }];

const okItem = (action: string, id: string) => ({ [action]: { _id: id, status: action === 'index' ? 201 : 200 } });
const errorItem = (action: string, id: string, status: number, type: string) => ({ [action]: { _id: id, status, error: { type, reason: `${type} on ${id}` } } });

describe('elBulk selective retry on partial (per-item) failures', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  beforeEach(async () => {
    vi.clearAllMocks();
    testMocks.info.mockResolvedValue({
      version: { number: '8.19.1' },
      tagline: 'You Know, for Search',
    });
    testMocks.putPipeline.mockResolvedValue({});
    await searchEngineInit();
  });

  it('passes through clean responses without any extra work', async () => {
    const data = { took: 1, errors: false, items: [okItem('index', 'a')] };
    testMocks.bulk.mockResolvedValue(data);
    await expect(elBulk({} as any, { refresh: true, body: indexOp('a') })).resolves.toEqual(data);
    expect(testMocks.bulk).toHaveBeenCalledTimes(1);
  });

  it('resubmits only the failed transient items and merges the results', async () => {
    vi.useFakeTimers();
    const body = [...indexOp('a'), ...updateOp('b'), ...deleteOp('c')];
    testMocks.bulk
      .mockResolvedValueOnce({
        took: 1,
        errors: true,
        items: [okItem('index', 'a'), errorItem('update', 'b', 429, 'es_rejected_execution_exception'), okItem('delete', 'c')],
      })
      .mockResolvedValueOnce({ took: 1, errors: false, items: [okItem('update', 'b')] });
    const bulkPromise = elBulk({} as any, { refresh: true, timeout: '1h', body });
    await vi.advanceTimersByTimeAsync(500);
    const result = await bulkPromise;
    expect(testMocks.bulk).toHaveBeenCalledTimes(2);
    // The second bulk carries ONLY the failed update operation (action line + source line)
    expect(testMocks.bulk.mock.calls[1][0].body).toEqual(updateOp('b'));
    expect(testMocks.bulk.mock.calls[1][0].refresh).toBe(true);
    // The merged response keeps the original item order and clears the errors flag
    expect(result.errors).toBe(false);
    expect(result.items.map((i: any) => (i.index ?? i.update ?? i.delete)._id)).toEqual(['a', 'b', 'c']);
    expect(logApp.warn).toHaveBeenCalledWith(
      expect.stringContaining('Bulk partial failure, retrying failed items'),
      expect.objectContaining({ opsTotal: 3, opsOk: 2, opsRetrying: 1, errorTypes: { es_rejected_execution_exception: 1 } }),
    );
    expect(logApp.info).toHaveBeenCalledWith(
      expect.stringContaining('Bulk recovered after partial failures'),
      expect.objectContaining({ attempts: 2, opsTotal: 3 }),
    );
  });

  it('detects and retries failed DELETE items (previously swallowed)', async () => {
    vi.useFakeTimers();
    const body = [...deleteOp('a'), ...deleteOp('b')];
    testMocks.bulk
      .mockResolvedValueOnce({
        took: 1,
        errors: true,
        items: [okItem('delete', 'a'), errorItem('delete', 'b', 429, 'es_rejected_execution_exception')],
      })
      .mockResolvedValueOnce({ took: 1, errors: false, items: [okItem('delete', 'b')] });
    const bulkPromise = elBulk({} as any, { refresh: true, body });
    await vi.advanceTimersByTimeAsync(500);
    const result = await bulkPromise;
    expect(testMocks.bulk).toHaveBeenCalledTimes(2);
    // Delete operations have no source line
    expect(testMocks.bulk.mock.calls[1][0].body).toEqual(deleteOp('b'));
    expect(result.errors).toBe(false);
  });

  it('retries version conflicts surviving retry_on_conflict (hot document contention)', async () => {
    vi.useFakeTimers();
    testMocks.bulk
      .mockResolvedValueOnce({
        took: 1,
        errors: true,
        items: [errorItem('update', 'hot', 409, 'version_conflict_engine_exception')],
      })
      .mockResolvedValueOnce({ took: 1, errors: false, items: [okItem('update', 'hot')] });
    const bulkPromise = elBulk({} as any, { body: updateOp('hot') });
    await vi.advanceTimersByTimeAsync(500);
    await expect(bulkPromise).resolves.toMatchObject({ errors: false });
    expect(testMocks.bulk).toHaveBeenCalledTimes(2);
  });

  it('fails fast on permanent item errors, without retrying', async () => {
    testMocks.bulk.mockResolvedValue({
      took: 1,
      errors: true,
      items: [okItem('index', 'a'), errorItem('index', 'b', 400, 'mapper_parsing_exception')],
    });
    const bulkPromise = elBulk({} as any, { body: [...indexOp('a'), ...indexOp('b')] });
    await expect(bulkPromise).rejects.toMatchObject({
      message: 'Bulk indexing fail',
      extensions: { code: 'DATABASE_ERROR', data: expect.objectContaining({ attempts: 1, bulkId: expect.any(String) }) },
    });
    expect(testMocks.bulk).toHaveBeenCalledTimes(1);
  });

  it('fails fast when transient and permanent errors are mixed', async () => {
    testMocks.bulk.mockResolvedValue({
      took: 1,
      errors: true,
      items: [errorItem('update', 'a', 429, 'es_rejected_execution_exception'), errorItem('index', 'b', 400, 'strict_dynamic_mapping_exception')],
    });
    await expect(elBulk({} as any, { body: [...updateOp('a'), ...indexOp('b')] })).rejects.toMatchObject({ message: 'Bulk indexing fail' });
    expect(testMocks.bulk).toHaveBeenCalledTimes(1);
  });

  it('still tolerates document_missing_exception on update without retrying', async () => {
    testMocks.bulk.mockResolvedValue({
      took: 1,
      errors: true,
      items: [errorItem('update', 'gone', 404, 'document_missing_exception')],
    });
    const result = await elBulk({} as any, { body: updateOp('gone') });
    expect(testMocks.bulk).toHaveBeenCalledTimes(1);
    // The tolerated error stays visible in the response items
    expect(result.errors).toBe(true);
  });

  it('gives up after the retry budget and reports the remaining errors with the bulkId', async () => {
    vi.useFakeTimers();
    testMocks.bulk.mockResolvedValue({
      took: 1,
      errors: true,
      items: [errorItem('update', 'a', 429, 'circuit_breaking_exception')],
    });
    const bulkPromise = elBulk({} as any, { body: updateOp('a') });
    const rejection = expect(bulkPromise).rejects.toMatchObject({
      message: 'Bulk indexing fail',
      extensions: {
        code: 'DATABASE_ERROR',
        data: expect.objectContaining({
          attempts: MAX_ATTEMPTS,
          bulkId: expect.any(String),
          errors: [expect.objectContaining({ type: 'circuit_breaking_exception' })],
        }),
      },
    });
    await vi.runAllTimersAsync();
    await rejection;
    expect(testMocks.bulk).toHaveBeenCalledTimes(MAX_ATTEMPTS);
  });

  it('keeps the request-level (transport) retry behavior of elRawBulk', async () => {
    vi.useFakeTimers();
    testMocks.bulk
      .mockRejectedValueOnce(new Error('circuit_breaking_exception: data too large'))
      .mockResolvedValueOnce({ took: 1, errors: false, items: [] });
    const bulkPromise = elBulk({} as any, { body: [] });
    await vi.advanceTimersByTimeAsync(500);
    await expect(bulkPromise).resolves.toMatchObject({ errors: false });
    expect(testMocks.bulk).toHaveBeenCalledTimes(2);
  });
});
