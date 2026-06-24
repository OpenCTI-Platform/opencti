import { logApp } from '../../../../src/config/conf';
import { type ManagerDefinition } from '../../../../src/manager/managerModule';

/**
 * This is an empty manager to validate manager module
 */
export const cronTestManager = async () => {
  logApp.info('[TEST] test manager is running');
};

export const TEST_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'TEST_MANAGER',
  label: 'Test manager',
  executionContext: 'test_manager',
  cronSchedulerHandler: {
    handler: cronTestManager,
    interval: 100,
    lockKey: 'test_manager_lock',
  },
  enabledByConfig: true,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};
