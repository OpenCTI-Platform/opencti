import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ManagerDefinition } from '../../../src/manager/managerModule';

const { registerManager } = vi.hoisted(() => ({ registerManager: vi.fn() }));

vi.mock('../../../src/manager/managerModule', () => ({
  registerManager,
}));

const registeredCleanupManagers = () => registerManager.mock.calls
  .map(([definition]) => definition as ManagerDefinition)
  .filter((definition) => definition.id === 'WORKFLOW_STATUS_CLEANUP_MANAGER');

const ENABLED_KEY = 'workflow_status_cleanup_manager:enabled';

const importManagerWithConf = async (enabled?: boolean) => {
  vi.resetModules();
  const { default: conf, ENABLED_FEATURE_FLAGS } = await import('../../../src/config/conf');
  // The manager must register without any feature flag turned on.
  ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
  if (enabled !== undefined) {
    conf.set(ENABLED_KEY, enabled);
  }
  await import('../../../src/manager/workflowStatusCleanupManager');
};

describe('Workflow status cleanup manager registration', () => {
  beforeEach(() => {
    registerManager.mockClear();
  });

  afterEach(async () => {
    const { default: conf } = await import('../../../src/config/conf');
    conf.clear(ENABLED_KEY);
  });

  it('registers the workflow status cleanup manager with the flag gone', async () => {
    await importManagerWithConf();

    // Other managers imported transitively also register, so only count this one.
    expect(registeredCleanupManagers()).toHaveLength(1);
    const [definition] = registeredCleanupManagers();
    expect(definition.enabled()).toBe(true);
    expect(definition.enabledToStart()).toBe(true);
  });

  it('is switched off by the workflow_status_cleanup_manager:enabled setting', async () => {
    await importManagerWithConf(false);

    expect(registeredCleanupManagers()).toHaveLength(1);
    const [definition] = registeredCleanupManagers();
    expect(definition.enabled()).toBe(false);
    expect(definition.enabledToStart()).toBe(false);
  });
});
