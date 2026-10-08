import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ManagerDefinition } from '../../../../src/manager/managerModule';

const {
  mockRegisterManager,
  mockConnectors,
  mockRedisGetConnectorStatus,
  mockRedisGetWork,
  mockElList,
  mockElUpdate,
  mockDeleteWorksRaw,
  mockLogInfo,
  mockLogWarn,
} = vi.hoisted(() => ({
  mockRegisterManager: vi.fn(),
  mockConnectors: vi.fn(),
  mockRedisGetConnectorStatus: vi.fn(),
  mockRedisGetWork: vi.fn(),
  mockElList: vi.fn(),
  mockElUpdate: vi.fn(),
  mockDeleteWorksRaw: vi.fn(),
  mockLogInfo: vi.fn(),
  mockLogWarn: vi.fn(),
}));

vi.mock('../../../../src/manager/managerModule', () => ({
  registerManager: mockRegisterManager,
}));

vi.mock('../../../../src/modules/connector/connector-domain', () => ({
  connectors: mockConnectors,
}));

vi.mock('../../../../src/database/redis', () => ({
  redisGetConnectorStatus: mockRedisGetConnectorStatus,
  redisGetWork: mockRedisGetWork,
}));

vi.mock('../../../../src/database/engine', () => ({
  elList: mockElList,
  elUpdate: mockElUpdate,
}));

vi.mock('../../../../src/domain/work', () => ({
  deleteWorksRaw: mockDeleteWorksRaw,
}));

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    logApp: {
      debug: vi.fn(),
      info: mockLogInfo,
      warn: mockLogWarn,
      error: vi.fn(),
    },
  };
});

import '../../../../src/modules/connector/connector-manager';

const definition: ManagerDefinition = mockRegisterManager.mock.calls[0][0];
const runConnectorManager = (signal = new AbortController().signal) => {
  return definition.cronSchedulerHandler!.handler({ signal });
};

const CONNECTOR = { internal_id: 'connector-1', name: 'Connector 1' };
const STATUS_TIMESTAMP = '2026-10-01T00:00:00.000Z';
const OLD_WORKS = [
  { _index: 'opencti_history-000001', internal_id: 'work-1' },
  { _index: 'opencti_history-000001', internal_id: 'work-2' },
];
const COMPLETED_WORKS = [{ _index: 'opencti_history-000001', internal_id: 'work-3' }];

// closeOldWorks lists the works with their timestamp, deleteCompletedWorks only their id
const isOldWorksQuery = (options: { baseFields: string[] }) => options.baseFields.includes('timestamp');

describe('connector manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConnectors.mockResolvedValue([CONNECTOR]);
    mockRedisGetConnectorStatus.mockResolvedValue(`connector-1_status_${STATUS_TIMESTAMP}`);
    mockRedisGetWork.mockResolvedValue({ import_processed_number: '12' });
    mockElList.mockImplementation(async (_context, _user, _indices, options) => {
      return options.callback(isOldWorksQuery(options) ? OLD_WORKS : COMPLETED_WORKS);
    });
  });

  it('should register a scheduled manager holding its lock during the run', () => {
    expect(definition).toMatchObject({
      id: 'CONNECTOR_MANAGER',
      label: 'Connector manager',
      executionContext: 'connector_manager',
      cronSchedulerHandler: {
        interval: 60000,
        lockKey: 'connector_manager_lock',
        lockInHandlerParams: true,
      },
    });
    expect(definition.cronSchedulerHandler?.runOnStart).toBeFalsy();
    // connector_manager:enabled defaults to true
    expect(definition.enabled()).toBe(true);
    expect(definition.enabledToStart()).toBe(true);
  });

  it('should force the completion of the works older than the connector status', async () => {
    await runConnectorManager();

    const oldWorksQuery = mockElList.mock.calls.map((call) => call[3]).find(isOldWorksQuery);
    expect(oldWorksQuery.filters.filters).toEqual([
      { key: ['connector_id'], values: ['connector-1'] },
      { key: ['status'], values: ['wait', 'progress'] },
      { key: ['timestamp'], values: [STATUS_TIMESTAMP], operator: 'lt' },
    ]);
    expect(mockElUpdate).toHaveBeenCalledTimes(2);
    expect(mockElUpdate).toHaveBeenCalledWith(expect.anything(), 'opencti_history-000001', 'work-1', {
      script: {
        source: expect.stringContaining('ctx._source[\'status\'] = "complete"'),
        lang: 'painless',
        params: { completed_time: expect.any(String), completed_number: 12 },
      },
    });
    expect(mockLogInfo).toHaveBeenCalledWith('Work completed by force due to age', { workId: 'work-2' });
  });

  it('should delete the completed works of each connector', async () => {
    await runConnectorManager();

    const deleteQuery = mockElList.mock.calls.map((call) => call[3]).find((options) => !isOldWorksQuery(options));
    expect(deleteQuery.filters.filters).toEqual([
      { key: ['connector_id'], values: ['connector-1'] },
      { key: ['status'], values: ['complete'] },
      { key: ['completed_time'], values: ['now-7d/d'], operator: 'lte' },
    ]);
    expect(mockDeleteWorksRaw).toHaveBeenCalledWith(expect.anything(), COMPLETED_WORKS);
  });

  it('should not look for old works when the connector has no status', async () => {
    mockRedisGetConnectorStatus.mockResolvedValue(null);

    await runConnectorManager();

    expect(mockElList).toHaveBeenCalledTimes(1);
    expect(isOldWorksQuery(mockElList.mock.calls[0][3])).toBe(false);
    expect(mockElUpdate).not.toHaveBeenCalled();
  });

  it('should leave the works without a status in redis untouched', async () => {
    mockRedisGetWork.mockImplementation(async (workId: string) => (workId === 'work-1' ? null : { import_processed_number: '3' }));

    await runConnectorManager();

    expect(mockElUpdate).toHaveBeenCalledTimes(1);
    expect(mockElUpdate).toHaveBeenCalledWith(expect.anything(), 'opencti_history-000001', 'work-2', expect.anything());
  });

  it('should log a work that cannot be completed and go on with the next one', async () => {
    const error = new Error('Elasticsearch unavailable');
    mockElUpdate.mockRejectedValueOnce(error);

    await runConnectorManager();

    expect(mockLogWarn).toHaveBeenCalledWith('[OPENCTI-MODULE] Connector manager error processing work closing', { cause: error });
    expect(mockElUpdate).toHaveBeenCalledTimes(2);
    expect(mockDeleteWorksRaw).toHaveBeenCalled();
  });

  it('should stop between connectors once its lock is lost', async () => {
    const controller = new AbortController();
    mockConnectors.mockResolvedValue([CONNECTOR, { internal_id: 'connector-2', name: 'Connector 2' }]);
    mockDeleteWorksRaw.mockImplementation(async () => controller.abort());

    await expect(runConnectorManager(controller.signal)).rejects.toThrow();

    expect(mockRedisGetConnectorStatus).toHaveBeenCalledTimes(1);
    expect(mockRedisGetConnectorStatus).toHaveBeenCalledWith('connector-1');
  });
});
