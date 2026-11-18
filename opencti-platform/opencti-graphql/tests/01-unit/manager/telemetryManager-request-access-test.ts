import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  addRequestAccessApprovedCount,
  addRequestAccessDeclinedCount,
  addWorkflowRequestAccessMigrationCount,
  addWorkflowRequestAccessPublishCount,
} from '../../../src/manager/telemetryManager';
import { redisSetTelemetryAdd } from '../../../src/database/redis';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/redis')>();
  return { ...actual, redisSetTelemetryAdd: vi.fn() };
});

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return { ...actual, logApp: { ...actual.logApp, warn: vi.fn() } };
});

const adders: Array<[string, () => void, string]> = [
  ['addWorkflowRequestAccessPublishCount', addWorkflowRequestAccessPublishCount, 'workflowRequestAccessPublishCount'],
  ['addWorkflowRequestAccessMigrationCount', addWorkflowRequestAccessMigrationCount, 'workflowRequestAccessMigrationCount'],
  ['addRequestAccessApprovedCount', addRequestAccessApprovedCount, 'requestAccessApprovedCount'],
  ['addRequestAccessDeclinedCount', addRequestAccessDeclinedCount, 'requestAccessDeclinedCount'],
];

describe('Request access telemetry counters', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe.each(adders)('%s', (_name, adder, gauge) => {
    it(`should increment ${gauge} by 1`, () => {
      vi.mocked(redisSetTelemetryAdd).mockResolvedValue(undefined as never);
      adder();
      expect(redisSetTelemetryAdd).toHaveBeenCalledWith(gauge, 1);
    });

    it('should not throw when redis fails', async () => {
      vi.mocked(redisSetTelemetryAdd).mockRejectedValue(new Error('redis down'));
      expect(() => adder()).not.toThrow();
      await vi.waitFor(() => expect(logApp.warn).toHaveBeenCalled());
    });
  });
});
