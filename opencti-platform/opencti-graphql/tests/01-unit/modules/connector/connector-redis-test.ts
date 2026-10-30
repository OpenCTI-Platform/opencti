import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockRedisGet = vi.fn();
const mockRedisSet = vi.fn();

vi.mock('../../../../src/database/redis', () => ({
  getClientBase: () => ({
    get: mockRedisGet,
    set: mockRedisSet,
  }),
}));

import { redisGetManagedConnectorAutoUpgradeStatus, redisSetManagedConnectorAutoUpgradeStatus } from '../../../../src/modules/connector/connector-redis';

describe('connector Redis', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should store the catalog manager initialization status', async () => {
    const status = {
      status: 'ready' as const,
      platformVersion: '7.2.0-test',
      startedAt: 100,
      completedAt: 200,
    };

    await redisSetManagedConnectorAutoUpgradeStatus(status);

    expect(mockRedisSet).toHaveBeenCalledWith('managed_connector_auto_upgrade_status', JSON.stringify(status));
  });

  it('should read the catalog manager initialization status', async () => {
    const status = {
      status: 'running',
      platformVersion: '7.2.0-test',
      startedAt: 100,
    };
    mockRedisGet.mockResolvedValue(JSON.stringify(status));

    await expect(redisGetManagedConnectorAutoUpgradeStatus()).resolves.toEqual(status);
  });

  it('should ignore an invalid catalog manager initialization status', async () => {
    mockRedisGet.mockResolvedValue('{invalid');

    await expect(redisGetManagedConnectorAutoUpgradeStatus()).resolves.toBeNull();
  });
});
