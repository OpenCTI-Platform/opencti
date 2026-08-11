import { beforeEach, describe, expect, it, vi } from 'vitest';

const findAllJsonIngestionMock = vi.fn();
const patchJsonIngestionMock = vi.fn();
const executeJsonQueryMock = vi.fn();
const queueDetailsMock = vi.fn();
const pushBundleToConnectorQueueMock = vi.fn();
const updateBuiltInConnectorInfoMock = vi.fn();

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
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

vi.mock('../../../../src/modules/ingestion/ingestion-json-domain', () => ({
  findAllJsonIngestion: findAllJsonIngestionMock,
  patchJsonIngestion: patchJsonIngestionMock,
  executeJsonQuery: executeJsonQueryMock,
}));

vi.mock('../../../../src/domain/connector', () => ({
  queueDetails: queueDetailsMock,
  connectorIdFromIngestId: (id: string) => `connector-${id}`,
}));

vi.mock('../../../../src/manager/ingestionManager/ingestionManagerPushToQueue', () => ({
  pushBundleToConnectorQueue: pushBundleToConnectorQueueMock,
  updateBuiltInConnectorInfo: updateBuiltInConnectorInfoMock,
}));

const jsonIngestion = {
  id: 'json--1',
  internal_id: 'json-internal--1',
  name: 'My JSON feed',
  user_id: 'user--1',
  scheduling_period: 'auto',
  last_execution_date: undefined,
  query_attributes: [
    { type: 'data', from: 'meta.offset', to: 'offset', exposed: 'query_param', state_operation: 'sum' },
  ],
};

const stixObjects = [
  { id: 'malware--1', type: 'malware', name: 'Malware test' },
  { id: 'relationship--1', type: 'relationship' },
];

describe('Ingestion manager - jsonExecutor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    queueDetailsMock.mockResolvedValue({ messages_number: 0, messages_size: 0 });
    patchJsonIngestionMock.mockResolvedValue({});
    pushBundleToConnectorQueueMock.mockResolvedValue(undefined);
    updateBuiltInConnectorInfoMock.mockResolvedValue(undefined);
    findAllJsonIngestionMock.mockResolvedValue([jsonIngestion]);
  });

  it('should push the fetched objects and save the next ingestion state on success', async () => {
    executeJsonQueryMock.mockResolvedValue({
      objects: stixObjects,
      variables: { offset: 10 },
      nextExecutionState: { offset: 5 },
    });

    const { jsonExecutor } = await import('../../../../src/manager/ingestionManager');

    await expect(jsonExecutor({} as any)).resolves.toBeUndefined();

    // The bundle built from the query result must be pushed to the connector queue
    expect(pushBundleToConnectorQueueMock).toHaveBeenCalledTimes(1);
    expect(pushBundleToConnectorQueueMock).toHaveBeenCalledWith(
      expect.anything(),
      jsonIngestion,
      expect.objectContaining({
        type: 'bundle',
        spec_version: '2.1',
        id: expect.stringMatching(/^bundle--/),
        objects: stixObjects,
      }),
    );

    // 'sum' state operation must merge previous variables with the new state
    expect(patchJsonIngestionMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'json-internal--1',
      expect.objectContaining({
        ingestion_json_state: { offset: 15 },
        last_execution_date: expect.any(String),
      }),
    );
    expect(updateBuiltInConnectorInfoMock).toHaveBeenCalledWith(
      expect.anything(),
      'user--1',
      'json--1',
      { state: { offset: 15 } },
    );
  });

  it('should not push any bundle when the query returns no object', async () => {
    executeJsonQueryMock.mockResolvedValue({ objects: [], variables: {}, nextExecutionState: {} });

    const { jsonExecutor } = await import('../../../../src/manager/ingestionManager');

    await expect(jsonExecutor({} as any)).resolves.toBeUndefined();

    expect(pushBundleToConnectorQueueMock).not.toHaveBeenCalled();
    expect(patchJsonIngestionMock).toHaveBeenCalledTimes(1);
  });

  it('should catch query errors, log them and only update the last execution date', async () => {
    executeJsonQueryMock.mockRejectedValue(new Error('Remote server unreachable'));

    const { jsonExecutor } = await import('../../../../src/manager/ingestionManager');
    const { logApp } = await import('../../../../src/config/conf');

    // The executor must never throw: a failing feed must not stop the ingestion manager
    await expect(jsonExecutor({} as any)).resolves.toBeUndefined();

    expect(pushBundleToConnectorQueueMock).not.toHaveBeenCalled();
    expect(logApp.warn).toHaveBeenCalledWith(
      expect.stringContaining('Json ingestion execution'),
      expect.objectContaining({ cause: expect.any(Error), name: 'My JSON feed' }),
    );
    // Only the last execution date is updated to respect the min interval on next run
    expect(patchJsonIngestionMock).toHaveBeenCalledTimes(1);
    expect(patchJsonIngestionMock).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'json-internal--1',
      { last_execution_date: expect.any(String) },
    );
  });

  it('should keep iterating over the other feeds when one of them fails', async () => {
    const failingIngestion = { ...jsonIngestion, id: 'json--ko', internal_id: 'json-internal--ko', name: 'Failing JSON feed' };
    findAllJsonIngestionMock.mockResolvedValue([failingIngestion, jsonIngestion]);
    executeJsonQueryMock
      .mockRejectedValueOnce(new Error('Remote server unreachable'))
      .mockResolvedValueOnce({ objects: stixObjects, variables: {}, nextExecutionState: {} });

    const { jsonExecutor } = await import('../../../../src/manager/ingestionManager');

    await expect(jsonExecutor({} as any)).resolves.toBeUndefined();

    expect(executeJsonQueryMock).toHaveBeenCalledTimes(2);
    expect(pushBundleToConnectorQueueMock).toHaveBeenCalledTimes(1);
    expect(pushBundleToConnectorQueueMock).toHaveBeenCalledWith(
      expect.anything(),
      jsonIngestion,
      expect.objectContaining({ objects: stixObjects }),
    );
  });

  it('should skip the execution when the connector queue is not empty', async () => {
    queueDetailsMock.mockResolvedValue({ messages_number: 12, messages_size: 1024 });

    const { jsonExecutor } = await import('../../../../src/manager/ingestionManager');

    await expect(jsonExecutor({} as any)).resolves.toBeUndefined();

    expect(executeJsonQueryMock).not.toHaveBeenCalled();
    expect(updateBuiltInConnectorInfoMock).toHaveBeenCalledWith(
      expect.anything(),
      'user--1',
      'json--1',
      { buffering: true, messages_size: 1024 },
    );
  });
});
