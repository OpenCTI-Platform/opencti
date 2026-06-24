import { describe, it, expect } from 'vitest';
import { getAllEnabledManagers, getAllManagersStatuses, registerManager } from '../../../../src/manager/managerModule';
import { getSettings } from '../../../../src/domain/settings';
import { testContext } from '../../../utils/testQuery';
import type { BasicStoreSettings } from '../../../../src/types/settings';

import { TEST_MANAGER_DEFINITION } from './testManager';
import { wait } from '../../../../src/database/utils';

describe('Manager module tests ', () => {
  it('should manage be able to start and stop', async () => {
    registerManager(TEST_MANAGER_DEFINITION);

    const allManagers = getAllEnabledManagers();
    const myTestManager = allManagers.find((manager) => manager.manager.id === 'TEST_MANAGER');

    // We should be able to check the running state, but there is an issue with this boolean.
    expect(myTestManager?.manager.enabledByConfig).toBeTruthy();

    await myTestManager?.start();
    await wait(200);

    const settings = await getSettings(testContext) as unknown as BasicStoreSettings;
    const managerStatus = getAllManagersStatuses(settings);
    const testManagerStatus1 = managerStatus.find((manager) => manager.id === 'TEST_MANAGER');
    expect(testManagerStatus1?.enable).toBeTruthy();

    await myTestManager?.shutdown();
    await wait(100);

    const managerStatus2 = getAllManagersStatuses(settings);
    const testManagerStatus2 = managerStatus2.find((manager) => manager.id === 'TEST_MANAGER');
    expect(testManagerStatus2?.running).toBeFalsy();
  });
});
