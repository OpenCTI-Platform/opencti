import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  patchCsvIngestionMock,
  findCsvIngestionByIdMock,
  generateAndSendBundleProcessMock,
  createWorkForIngestionMock,
  updateBuiltInConnectorInfoMock,
  updateExpectationsNumberMock,
  reportExpectationMock,
  findUserByIdMock,
} = vi.hoisted(() => ({
  patchCsvIngestionMock: vi.fn(),
  findCsvIngestionByIdMock: vi.fn(),
  generateAndSendBundleProcessMock: vi.fn(),
  createWorkForIngestionMock: vi.fn(),
  updateBuiltInConnectorInfoMock: vi.fn(),
  updateExpectationsNumberMock: vi.fn(),
  reportExpectationMock: vi.fn(),
  findUserByIdMock: vi.fn(),
}));

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    logApp: {
      ...actual.logApp,
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
  };
});

vi.mock('../../../../src/modules/ingestion/ingestion-csv-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/ingestion/ingestion-csv-domain')>()),
  patchCsvIngestion: patchCsvIngestionMock,
  findById: findCsvIngestionByIdMock,
}));

vi.mock('../../../../src/parser/csv-bundler', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/parser/csv-bundler')>()),
  generateAndSendBundleProcess: generateAndSendBundleProcessMock,
}));

vi.mock('../../../../src/manager/ingestionManager/ingestionManagerPushToQueue', () => ({
  createWorkForIngestion: createWorkForIngestionMock,
  pushBundleToConnectorQueue: vi.fn(),
  updateBuiltInConnectorInfo: updateBuiltInConnectorInfoMock,
}));

vi.mock('../../../../src/domain/work', () => ({
  updateExpectationsNumber: updateExpectationsNumberMock,
  reportExpectation: reportExpectationMock,
}));

vi.mock('../../../../src/modules/user/user-domain', () => ({
  findById: findUserByIdMock,
}));

vi.mock('../../../../src/modules/ingestion/ingestion-execution-identity', () => ({
  assertIngestionExecutionIdentityAllowed: vi.fn(),
}));

const csvIngestion = {
  id: 'csv--1',
  internal_id: 'csv-internal--1',
  name: 'My CSV feed',
  user_id: 'user--1',
  current_state_hash: 'previous-hash',
} as any;

const csvMapper = { has_header: false, skipLineChar: '#' } as any;

describe('Ingestion manager - processCsvLines stop', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createWorkForIngestionMock.mockResolvedValue({ id: 'work--1' });
    findUserByIdMock.mockResolvedValue({ id: 'user--1' });
    patchCsvIngestionMock.mockResolvedValue({});
  });

  it('should keep the previous feed state when the feed was stopped during the run', async () => {
    generateAndSendBundleProcessMock.mockResolvedValue({ bundleCount: 1, objectCount: 3, aborted: true });

    const { processCsvLines } = await import('../../../../src/manager/ingestionManager');

    const result = await processCsvLines({ user: undefined } as any, csvIngestion, csvMapper, ['a,b\n', 'c,d\n'], undefined);

    expect(result).toEqual({ isUnchangedData: false, objectsInBundleCount: 3 });
    expect(patchCsvIngestionMock).not.toHaveBeenCalled();
    expect(updateBuiltInConnectorInfoMock).not.toHaveBeenCalled();
    // The stop check given to the bundler re-reads the feed by its internal id
    const { isStopped } = generateAndSendBundleProcessMock.mock.calls[0][2];
    findCsvIngestionByIdMock.mockResolvedValueOnce({ ingestion_running: false });
    await expect(isStopped()).resolves.toBe(true);
    expect(findCsvIngestionByIdMock).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'csv-internal--1');
  });

  it('should advance the feed state when the run was not stopped', async () => {
    generateAndSendBundleProcessMock.mockResolvedValue({ bundleCount: 1, objectCount: 3, aborted: false });

    const { processCsvLines } = await import('../../../../src/manager/ingestionManager');

    await processCsvLines({ user: undefined } as any, csvIngestion, csvMapper, ['a,b\n', 'c,d\n'], undefined);

    expect(patchCsvIngestionMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'csv-internal--1',
      expect.objectContaining({ current_state_hash: expect.any(String), last_execution_date: expect.any(String) }),
    );
  });
});
