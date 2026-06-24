import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as sanityManagerConfigMock from '../../../../src/manager/dataSanityManager/dataSanityManager-configuration';
import { dataSanityHandler } from '../../../../src/manager/dataSanityManager';
import { findDataSanityByFixName, setForceRun } from '../../../../src/modules/dataSanity/dataSanity-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

describe('Data sanity manager handler test coverage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(sanityManagerConfigMock, 'sanityFixList').mockReturnValue([
      {
        name: 'mockRunOnceFix',
        fn: async () => {
          return { message: 'Output of mockRunOnceFix' };
        },
        execution_type: 'run_once',
      }, {
        name: 'mockRunPeriodicFix',
        fn: async () => {
          return { message: 'Output of mockRunPeriodicFix' };
        },
        execution_type: 'periodic',
      }, {
        name: 'mockRunOnDemandFix',
        fn: async () => {
          return { message: 'Output of mockRunOnDemandFix' };
        },
        execution_type: 'on_demand',
      },
    ]);
  });

  let runOnceFirstRunDate: Date;
  let runOncePeriodicRunDate: Date;

  it('should on first run, execute new fixes from the list', async () => {
    await dataSanityHandler();

    // Check run_once fix has been executed
    const runOnceFix = await findDataSanityByFixName(testContext, 'mockRunOnceFix');
    expect(runOnceFix).toBeDefined();
    expect(runOnceFix?.fix_name).toBe('mockRunOnceFix');
    expect(runOnceFix?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(runOnceFix?.last_failure_message).toBe('');
    expect(runOnceFix?.force_run).toBe(false);
    if (runOnceFix?.last_run_date) {
      runOnceFirstRunDate = runOnceFix?.last_run_date;
    }

    // Check periodic fix has been executed
    const periodicFix = await findDataSanityByFixName(testContext, 'mockRunPeriodicFix');
    expect(periodicFix).toBeDefined();
    expect(periodicFix?.fix_name).toBe('mockRunPeriodicFix');
    expect(periodicFix?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(periodicFix?.last_failure_message).toBe('');
    expect(periodicFix?.force_run).toBe(false);
    if (periodicFix?.last_run_date) {
      runOncePeriodicRunDate = periodicFix?.last_run_date;
    }

    // Check on_demand fix is registered but has NOT been executed (no meaningful run date)
    const onDemandFix = await findDataSanityByFixName(testContext, 'mockRunOnDemandFix');
    expect(onDemandFix).toBeDefined();
    expect(onDemandFix?.fix_name).toBe('mockRunOnDemandFix');
    expect(onDemandFix?.last_execution_time).toBe(0);
    expect(onDemandFix?.last_failure_message).toBe('');
    expect(onDemandFix?.force_run).toBe(false);
  });

  it('should on second run, execute only periodic fixes from the list', async () => {
    await dataSanityHandler();

    // Check run_once fix has been executed
    const runOnceFix = await findDataSanityByFixName(testContext, 'mockRunOnceFix');
    expect(runOnceFix).toBeDefined();
    expect(runOnceFix?.last_run_date).toBe(runOnceFirstRunDate);

    // Check periodic fix has been executed
    const periodicFix = await findDataSanityByFixName(testContext, 'mockRunPeriodicFix');
    expect(periodicFix).toBeDefined();
    expect(periodicFix?.last_run_date).not.toBe(runOncePeriodicRunDate);

    // Check on_demand fix is registered but has NOT been executed (no meaningful run date)
    const onDemandFix = await findDataSanityByFixName(testContext, 'mockRunOnDemandFix');
    expect(onDemandFix).toBeDefined();
    expect(onDemandFix?.fix_name).toBe('mockRunOnDemandFix');
    expect(onDemandFix?.last_execution_time).toBe(0);
    expect(onDemandFix?.last_failure_message).toBe('');
    expect(onDemandFix?.force_run).toBe(false);
  });

  it('should run on demand be executed', async () => {
    // GIVEN a force run has been requested
    await setForceRun(testContext, ADMIN_USER, 'mockRunOnDemandFix');

    const onDemandFix = await findDataSanityByFixName(testContext, 'mockRunOnDemandFix');
    expect(onDemandFix).toBeDefined();
    expect(onDemandFix?.fix_name).toBe('mockRunOnDemandFix');
    expect(onDemandFix?.last_execution_time).toBe(0); // not run yet
    expect(onDemandFix?.force_run).toBe(true);// this mean it's planned

    // WHEN manager handler runs
    await dataSanityHandler();

    // THEN
    const onDemandFixAfterRun = await findDataSanityByFixName(testContext, 'mockRunOnDemandFix');
    expect(onDemandFixAfterRun).toBeDefined();
    expect(onDemandFixAfterRun?.fix_name).toBe('mockRunOnDemandFix');
    expect(onDemandFixAfterRun?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(onDemandFixAfterRun?.last_failure_message).toBe('');
    expect(onDemandFixAfterRun?.force_run).toBe(false); // should be back to false
  });
});
