import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ManagerDefinition } from '../../../src/manager/managerModule';

// Mock all heavy dependencies before importing the module under test
vi.mock('set-interval-async/fixed', () => ({
  setIntervalAsync: vi.fn().mockReturnValue({}),
  clearIntervalAsync: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('set-interval-async/dynamic', () => ({
  setIntervalAsync: vi.fn().mockReturnValue({}),
  clearIntervalAsync: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('moment/moment', () => ({
  default: vi.fn(() => ({
    diff: vi.fn(() => 0),
  })),
  duration: vi.fn(() => ({ asMilliseconds: vi.fn(() => 0) })),
}));

vi.mock('../../../src/database/stream/stream-handler', () => ({
  createStreamProcessor: vi.fn(),
}));

vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: {
      info: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
  };
});

vi.mock('../../../src/config/errors', () => ({
  TYPE_LOCK_ERROR: 'LockTimeoutError',
}));

vi.mock('../../../src/utils/format', () => ({
  utcDate: vi.fn(() => new Date()),
}));

vi.mock('../../../src/enterprise-edition/ee', () => ({
  isEnterpriseEditionFromSettings: vi.fn(() => false),
}));

// Helper to build a minimal ManagerDefinition for testing
const buildManagerDefinition = (id: string, enabledToStart: boolean, enabledBySettings = true): ManagerDefinition => ({
  id,
  label: `Test Manager ${id}`,
  executionContext: 'test',
  enabledByConfig: enabledToStart,
  enabled: () => enabledBySettings,
  enabledToStart: () => enabledToStart,
});

describe('managerModule', () => {
  // Each test gets a fresh module with an empty managers registry
  let registerManager: (manager: ManagerDefinition) => void;
  let getAllEnabledManagers: () => unknown[];
  let getAllDisabledManagers: () => unknown[];
  let startAllManagers: () => Promise<void>;
  let shutdownAllManagers: () => Promise<void>;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();
    const module = await import('../../../src/manager/managerModule');
    registerManager = module.registerManager;
    getAllEnabledManagers = module.getAllEnabledManagers;
    getAllDisabledManagers = module.getAllDisabledManagers;
    startAllManagers = module.startAllManagers;
    shutdownAllManagers = module.shutdownAllManagers;
  });

  describe('getAllEnabledManagers', () => {
    it('should return an empty array when no managers are registered', () => {
      expect(getAllEnabledManagers()).toEqual([]);
    });

    it('should return only managers where enabledToStart() is true', () => {
      registerManager(buildManagerDefinition('mgr-enabled-1', true));
      registerManager(buildManagerDefinition('mgr-disabled-1', false));
      registerManager(buildManagerDefinition('mgr-enabled-2', true));

      const enabled = getAllEnabledManagers() as Array<{ manager: ManagerDefinition }>;
      expect(enabled).toHaveLength(2);
      expect(enabled.map((m) => m.manager.id)).toEqual(['mgr-enabled-1', 'mgr-enabled-2']);
    });

    it('should return all managers when all are enabled', () => {
      registerManager(buildManagerDefinition('mgr-1', true));
      registerManager(buildManagerDefinition('mgr-2', true));

      const enabled = getAllEnabledManagers();
      expect(enabled).toHaveLength(2);
    });

    it('should return empty array when all managers are disabled', () => {
      registerManager(buildManagerDefinition('mgr-1', false));
      registerManager(buildManagerDefinition('mgr-2', false));

      expect(getAllEnabledManagers()).toHaveLength(0);
    });
  });

  describe('getAllDisabledManagers', () => {
    it('should return an empty array when no managers are registered', () => {
      expect(getAllDisabledManagers()).toEqual([]);
    });

    it('should return only managers where enabledToStart() is false', () => {
      registerManager(buildManagerDefinition('mgr-enabled-1', true));
      registerManager(buildManagerDefinition('mgr-disabled-1', false));
      registerManager(buildManagerDefinition('mgr-disabled-2', false));

      const disabled = getAllDisabledManagers() as Array<{ manager: ManagerDefinition }>;
      expect(disabled).toHaveLength(2);
      expect(disabled.map((m) => m.manager.id)).toEqual(['mgr-disabled-1', 'mgr-disabled-2']);
    });

    it('should return all managers when all are disabled', () => {
      registerManager(buildManagerDefinition('mgr-1', false));
      registerManager(buildManagerDefinition('mgr-2', false));

      const disabled = getAllDisabledManagers();
      expect(disabled).toHaveLength(2);
    });

    it('should return empty array when all managers are enabled', () => {
      registerManager(buildManagerDefinition('mgr-1', true));
      registerManager(buildManagerDefinition('mgr-2', true));

      expect(getAllDisabledManagers()).toHaveLength(0);
    });
  });

  describe('getAllEnabledManagers and getAllDisabledManagers are complementary', () => {
    it('should partition managers into enabled and disabled without overlap', () => {
      registerManager(buildManagerDefinition('mgr-enabled', true));
      registerManager(buildManagerDefinition('mgr-disabled', false));

      const enabled = getAllEnabledManagers() as Array<{ manager: ManagerDefinition }>;
      const disabled = getAllDisabledManagers() as Array<{ manager: ManagerDefinition }>;

      const enabledIds = new Set(enabled.map((m) => m.manager.id));
      const disabledIds = new Set(disabled.map((m) => m.manager.id));

      // No manager should appear in both lists
      const overlap = [...enabledIds].filter((id) => disabledIds.has(id));
      expect(overlap).toHaveLength(0);

      // Together they should cover all registered managers
      expect(enabled.length + disabled.length).toBe(2);
    });
  });

  describe('startAllManagers', () => {
    it('should start all enabled managers in parallel', async () => {
      const { setIntervalAsync } = await import('set-interval-async/fixed');
      const mockSetInterval = vi.mocked(setIntervalAsync);

      registerManager({
        ...buildManagerDefinition('mgr-1', true),
        cronSchedulerHandler: {
          handler: vi.fn(),
          interval: 1000,
          lockKey: 'test-lock-1',
        },
      });
      registerManager({
        ...buildManagerDefinition('mgr-2', true),
        cronSchedulerHandler: {
          handler: vi.fn(),
          interval: 2000,
          lockKey: 'test-lock-2',
        },
      });

      await startAllManagers();

      // Both managers should have had their cron scheduler started
      expect(mockSetInterval).toHaveBeenCalledTimes(2);
    });

    it('should not start disabled managers', async () => {
      const { setIntervalAsync } = await import('set-interval-async/fixed');
      const mockSetInterval = vi.mocked(setIntervalAsync);

      registerManager({
        ...buildManagerDefinition('mgr-enabled', true),
        cronSchedulerHandler: {
          handler: vi.fn(),
          interval: 1000,
          lockKey: 'test-lock-enabled',
        },
      });
      registerManager(buildManagerDefinition('mgr-disabled', false));

      await startAllManagers();

      // Only enabled manager should have been started
      expect(mockSetInterval).toHaveBeenCalledTimes(1);
    });

    it('should log disabled managers as not started', async () => {
      const { logApp } = await import('../../../src/config/conf');

      registerManager(buildManagerDefinition('mgr-disabled', false));

      await startAllManagers();

      expect(logApp.info).toHaveBeenCalledWith(
        expect.stringContaining('not started (disabled by configuration)')
      );
    });
  });

  describe('shutdownAllManagers', () => {
    it('should shutdown all enabled managers', async () => {
      const { setIntervalAsync } = await import('set-interval-async/fixed');
      const { clearIntervalAsync } = await import('set-interval-async/fixed');
      const mockSetInterval = vi.mocked(setIntervalAsync);
      const mockClearInterval = vi.mocked(clearIntervalAsync);

      const mockTimer = { id: 'mock-timer' };
      mockSetInterval.mockReturnValue(mockTimer as unknown as ReturnType<typeof setIntervalAsync>);

      registerManager({
        ...buildManagerDefinition('mgr-1', true),
        cronSchedulerHandler: {
          handler: vi.fn(),
          interval: 1000,
          lockKey: 'test-lock-1',
        },
      });

      await startAllManagers();
      await shutdownAllManagers();

      // clearIntervalAsync should have been called to clean up the scheduler
      expect(mockClearInterval).toHaveBeenCalledWith(mockTimer);
    });
  });
});
