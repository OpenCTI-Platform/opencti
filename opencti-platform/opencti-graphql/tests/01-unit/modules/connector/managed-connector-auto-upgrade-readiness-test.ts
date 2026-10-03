import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockRedisGetManagedConnectorAutoUpgradeStatus = vi.fn();
const mockLogWarn = vi.fn();
const mockIsCatalogManagerEnabled = vi.fn(() => true);

vi.mock('../../../../src/config/conf', () => ({
  logApp: {
    warn: mockLogWarn,
  },
  PLATFORM_VERSION: '7.2.0-test',
}));

vi.mock('../../../../src/modules/catalog/catalog-manager', () => ({
  isCatalogManagerEnabled: mockIsCatalogManagerEnabled,
}));

vi.mock('../../../../src/modules/connector/connector-redis', () => ({
  redisGetManagedConnectorAutoUpgradeStatus: mockRedisGetManagedConnectorAutoUpgradeStatus,
}));

describe('managed connector auto-upgrade readiness', () => {
  beforeEach(() => {
    vi.useRealTimers();
    vi.resetModules();
    mockRedisGetManagedConnectorAutoUpgradeStatus.mockReset();
    mockLogWarn.mockReset();
    mockIsCatalogManagerEnabled.mockReset();
    mockIsCatalogManagerEnabled.mockReturnValue(true);
  });

  it('should use a fixed bounded timeout', async () => {
    vi.useFakeTimers();
    mockRedisGetManagedConnectorAutoUpgradeStatus.mockResolvedValue(null);
    const readiness = await import('../../../../src/modules/connector/managed-connector-auto-upgrade-readiness');

    const waiting = readiness.waitForManagedConnectorAutoUpgrade();
    const rejection = expect(waiting).rejects.toThrow('Managed connector auto-upgrade timed out');
    await vi.advanceTimersByTimeAsync(90_000);

    await rejection;
  });

  it('should skip readiness when the catalog manager is disabled', async () => {
    mockIsCatalogManagerEnabled.mockReturnValue(false);
    const readiness = await import('../../../../src/modules/connector/managed-connector-auto-upgrade-readiness');

    await expect(readiness.waitForManagedConnectorAutoUpgrade()).resolves.toBeUndefined();
    expect(mockRedisGetManagedConnectorAutoUpgradeStatus).not.toHaveBeenCalled();
  });

  it('should accept a shared ready status', async () => {
    const now = Date.now();
    mockRedisGetManagedConnectorAutoUpgradeStatus.mockResolvedValue({
      status: 'ready',
      platformVersion: '7.2.0-test',
      startedAt: now,
      completedAt: now,
    });
    const readiness = await import('../../../../src/modules/connector/managed-connector-auto-upgrade-readiness');

    await expect(readiness.waitForManagedConnectorAutoUpgrade()).resolves.toBeUndefined();
  });

  it('should ignore ready statuses from another platform version', async () => {
    vi.useFakeTimers();
    mockRedisGetManagedConnectorAutoUpgradeStatus.mockResolvedValue({
      status: 'ready',
      platformVersion: '7.1.0-test',
      startedAt: Date.now() - 60_000,
      completedAt: Date.now() - 60_000,
    });
    const readiness = await import('../../../../src/modules/connector/managed-connector-auto-upgrade-readiness');

    const waiting = readiness.waitForManagedConnectorAutoUpgrade();
    const rejection = expect(waiting).rejects.toThrow('Managed connector auto-upgrade timed out');
    await vi.advanceTimersByTimeAsync(90_000);

    await rejection;
  });

  it('should use persisted connector snapshots when auto-upgrade fails', async () => {
    mockRedisGetManagedConnectorAutoUpgradeStatus.mockResolvedValue({
      status: 'failed',
      platformVersion: '7.2.0-test',
      startedAt: Date.now(),
      completedAt: Date.now(),
      error: 'auto-upgrade failed',
    });
    const readiness = await import('../../../../src/modules/connector/managed-connector-auto-upgrade-readiness');

    await expect(readiness.waitForManagedConnectorAutoUpgrade()).resolves.toBeUndefined();
    expect(mockLogWarn).toHaveBeenCalledWith(
      '[OPENCTI-MODULE] Managed connector auto-upgrade failed, using persisted connector snapshots',
      {
        module: 'connector',
        cause: 'auto-upgrade failed',
      },
    );
  });
});
