import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const testMocks = vi.hoisted(() => ({
  update: vi.fn(),
  delete: vi.fn(),
  reindex: vi.fn(),
  info: vi.fn(),
  putPipeline: vi.fn(),
  confGet: vi.fn(),
}));

vi.mock('@elastic/elasticsearch', () => {
  class MockElkClient {
    public ingest = { putPipeline: testMocks.putPipeline };

    public info = testMocks.info;

    public update = testMocks.update;

    public delete = testMocks.delete;

    public reindex = testMocks.reindex;

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

import { elDelete, elReindexElements, elUpdate, searchEngineInit } from '../../../src/database/engine';

const TRANSIENT_ERROR = new Error('circuit_breaking_exception: data too large');
const MAX_RETRY_ATTEMPTS = 6;

describe('engine retries on circuit breaking exception', () => {
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

  describe('elUpdate', () => {
    it('retries after circuit_breaking_exception', async () => {
      vi.useFakeTimers();
      testMocks.update
        .mockRejectedValueOnce(TRANSIENT_ERROR)
        .mockResolvedValueOnce({});
      const updatePromise = elUpdate({} as any, 'entities', 'entity-1', { entity_type: 'Report' });
      await vi.advanceTimersByTimeAsync(500);
      await expect(updatePromise).resolves.toEqual({});
      expect(testMocks.update).toHaveBeenCalledTimes(2);
    });

    it('throws higher level exception when retries are exhausted', async () => {
      vi.useFakeTimers();
      testMocks.update.mockRejectedValue(TRANSIENT_ERROR);
      const updatePromise = elUpdate({} as any, 'entities', 'entity-1', { entity_type: 'Report' });
      const rejectionAssertion = expect(updatePromise).rejects.toMatchObject({
        message: 'Update indexing fail',
        extensions: { code: 'DATABASE_ERROR' },
      });
      await vi.runAllTimersAsync();
      await rejectionAssertion;
      expect(testMocks.update).toHaveBeenCalledTimes(MAX_RETRY_ATTEMPTS);
    });
  });

  describe('elDelete', () => {
    it('retries after circuit_breaking_exception', async () => {
      vi.useFakeTimers();
      testMocks.delete
        .mockRejectedValueOnce(TRANSIENT_ERROR)
        .mockResolvedValueOnce({});
      const deletePromise = elDelete('entities', 'entity-1');
      await vi.advanceTimersByTimeAsync(500);
      await expect(deletePromise).resolves.toEqual({});
      expect(testMocks.delete).toHaveBeenCalledTimes(2);
    });

    it('throws higher level exception when retries are exhausted', async () => {
      vi.useFakeTimers();
      testMocks.delete.mockRejectedValue(TRANSIENT_ERROR);
      const deletePromise = elDelete('entities', 'entity-1');
      const rejectionAssertion = expect(deletePromise).rejects.toMatchObject({
        message: 'Deleting indexing fail',
        extensions: { code: 'DATABASE_ERROR' },
      });
      await vi.runAllTimersAsync();
      await rejectionAssertion;
      expect(testMocks.delete).toHaveBeenCalledTimes(MAX_RETRY_ATTEMPTS);
    });
  });

  describe('elReindexElements', () => {
    it('retries after circuit_breaking_exception', async () => {
      vi.useFakeTimers();
      testMocks.reindex
        .mockRejectedValueOnce(TRANSIENT_ERROR)
        .mockResolvedValueOnce({});
      const reindexPromise = elReindexElements({} as any, {} as any, ['entity-1'], 'src_entities', 'dest_entities');
      await vi.advanceTimersByTimeAsync(500);
      await expect(reindexPromise).resolves.toEqual({});
      expect(testMocks.reindex).toHaveBeenCalledTimes(2);
    });

    it('throws higher level exception when retries are exhausted', async () => {
      vi.useFakeTimers();
      testMocks.reindex.mockRejectedValue(TRANSIENT_ERROR);
      const reindexPromise = elReindexElements({} as any, {} as any, ['entity-1'], 'src_entities', 'dest_entities');
      const rejectionAssertion = expect(reindexPromise).rejects.toMatchObject({
        message: 'Reindexing fail from src_entities to dest_entities',
        extensions: { code: 'DATABASE_ERROR' },
      });
      await vi.runAllTimersAsync();
      await rejectionAssertion;
      expect(testMocks.reindex).toHaveBeenCalledTimes(MAX_RETRY_ATTEMPTS);
    });
  });
});
