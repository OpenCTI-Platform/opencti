import { describe, it, expect } from 'vitest';
import { getAllEnabledManagers, getAllManagersStatuses, registerManager, shutdownAllManagers, startAllManagers } from '../../../../src/manager/managerModule';
import { getSettings } from '../../../../src/domain/settings';
import { testContext } from '../../../utils/testQuery';
import type { BasicStoreSettings } from '../../../../src/types/settings';

// Enable testManager to run
import './testManager';
import { TEST_MANAGER_DEFINITION } from './testManager';

describe('Manager module tests ', () => {
  it('should startup and shutdown and startup be a noop', async () => {
    registerManager(TEST_MANAGER_DEFINITION);
    await startAllManagers();

    const allManagers = getAllEnabledManagers();
    const myTestManager = allManagers.find((manager) => manager.manager.id === 'TEST_MANAGER');

    // We should be able to check the running state, but there is an issue with this boolean.
    expect(myTestManager?.manager.enabledByConfig).toBeTruthy();

    const settings = await getSettings(testContext) as unknown as BasicStoreSettings;
    const managerStatus = getAllManagersStatuses(settings);
    const testManagerStatus1 = managerStatus.find((manager) => manager.id === 'TEST_MANAGER');
    expect(testManagerStatus1?.enable).toBeTruthy();

    await shutdownAllManagers();

    await startAllManagers();
    const managerStatusAtTheEnd = getAllManagersStatuses(settings);
    const testManagerStatusAtTheEnd = managerStatusAtTheEnd.find((manager) => manager.id === 'TEST_MANAGER');
    expect(testManagerStatusAtTheEnd?.enable).toBeTruthy();
  });
});
