import { afterEach, describe, expect, it, vi } from 'vitest';
import { registerManager, getAllEnabledManagers, type ManagerDefinition } from '../../../../src/manager/managerModule';
import { wait } from '../../../../src/database/utils';
import * as ee from '../../../../src/enterprise-edition/ee';
import * as masterLock from '../../../../src/lock/master-lock';

describe('Manager module: enterprise edition gate', () => {
  afterEach(async () => {
    vi.restoreAllMocks();
  });

  const mockLock = () => {
    vi.spyOn(masterLock, 'lockResources').mockResolvedValue({
      operation: 'test-op',
      signal: new AbortController().signal,
      unlock: vi.fn(),
    } as any);
  };

  const buildEeOnlyManager = (id: string, handler: () => Promise<void>): ManagerDefinition => ({
    id,
    label: `Test EE manager ${id}`,
    executionContext: 'test_ee_manager',
    enterpriseEditionOnly: true,
    cronSchedulerHandler: {
      handler,
      interval: 50,
      lockKey: `${id}_lock`,
    },
    enabledByConfig: true,
    enabledToStart(): boolean {
      return this.enabledByConfig;
    },
    enabled(): boolean {
      return this.enabledByConfig;
    },
  });

  it('should not call the handler of an enterpriseEditionOnly manager when EE is disabled', async () => {
    mockLock();
    vi.spyOn(ee, 'isEnterpriseEditionAuthorized').mockResolvedValue(false);
    const handler = vi.fn().mockResolvedValue(undefined);
    const managerDefinition = buildEeOnlyManager('TEST_EE_MANAGER_DISABLED', handler);
    registerManager(managerDefinition);
    const registeredManager = getAllEnabledManagers().find((m) => m.manager.id === managerDefinition.id);

    await registeredManager?.start();
    await wait(200);
    await registeredManager?.shutdown();

    expect(handler).not.toHaveBeenCalled();
  });

  it('should call the handler of an enterpriseEditionOnly manager when EE is enabled', async () => {
    mockLock();
    vi.spyOn(ee, 'isEnterpriseEditionAuthorized').mockResolvedValue(true);
    const handler = vi.fn().mockResolvedValue(undefined);
    const managerDefinition = buildEeOnlyManager('TEST_EE_MANAGER_ENABLED', handler);
    registerManager(managerDefinition);
    const registeredManager = getAllEnabledManagers().find((m) => m.manager.id === managerDefinition.id);

    await registeredManager?.start();
    await wait(200);
    await registeredManager?.shutdown();

    expect(handler).toHaveBeenCalled();
  });

  it('should call the handler of a non-enterpriseEditionOnly manager regardless of EE state', async () => {
    mockLock();
    const handler = vi.fn().mockResolvedValue(undefined);
    const managerDefinition: ManagerDefinition = {
      id: 'TEST_CE_MANAGER',
      label: 'Test CE manager',
      executionContext: 'test_ce_manager',
      cronSchedulerHandler: {
        handler,
        interval: 50,
        lockKey: 'test_ce_manager_lock',
      },
      enabledByConfig: true,
      enabledToStart(): boolean {
        return this.enabledByConfig;
      },
      enabled(): boolean {
        return this.enabledByConfig;
      },
    };
    registerManager(managerDefinition);
    const registeredManager = getAllEnabledManagers().find((m) => m.manager.id === managerDefinition.id);

    await registeredManager?.start();
    await wait(200);
    await registeredManager?.shutdown();

    expect(handler).toHaveBeenCalled();
  });
});
