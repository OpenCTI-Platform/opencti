import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as sanityManagerConfigMock from '../../../../src/modules/dataSanity/dataSanity-configuration';
import { dataSanityHandler } from '../../../../src/manager/dataSanityManager';
import { findDataSanityByOperationName, setForceRun } from '../../../../src/modules/dataSanity/dataSanity-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

describe('Data sanity manager handler test coverage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(sanityManagerConfigMock, 'sanityOperationList').mockReturnValue([
      {
        name: 'mockRunOnceOperation',
        dryRun: async () => {
          return { message: 'Dry run of mockRunOnceOperation', estimated_impact: { Malware: 2 } };
        },
        operationRun: async () => {
          return { message: 'Output of mockRunOnceOperation', impact: { Malware: 2 } };
        },
        execution_type: 'run_once',
      }, {
        name: 'mockRunPeriodicOperation',
        dryRun: async () => {
          return { message: 'Dry run of mockRunPeriodicOperation', estimated_impact: { Indicator: 5 } };
        },
        operationRun: async () => {
          return { message: 'Output of mockRunPeriodicOperation', impact: { Indicator: 5 } };
        },
        execution_type: 'periodic',
      }, {
        name: 'mockRunOnDemandOperation',
        dryRun: async () => {
          return { message: 'Dry run of mockRunOnDemandOperation', estimated_impact: { Report: 1 } };
        },
        operationRun: async () => {
          return { message: 'Output of mockRunOnDemandOperation', impact: { Report: 1 } };
        },
        execution_type: 'on_demand',
      }, {
        name: 'mockRunOnDemandOperation2',
        dryRun: async () => {
          return { message: 'Dry run of mockRunOnDemandOperation2', estimated_impact: {} };
        },
        operationRun: async () => {
          return { message: 'Output of second mockRunOnDemandOperation', impact: {} };
        },
        execution_type: 'on_demand',
      }, {
        name: 'mockRunOnceOperationThatFails',
        dryRun: async () => {
          return { message: 'Dry run of mockRunOnceOperationThatFails', estimated_impact: { Vulnerability: 3 } };
        },
        operationRun: async () => {
          throw Error('This is raising error - mockRunOnceOperationThatFails');
        },
        execution_type: 'on_demand',
      },
    ]);
  });

  let runOnceFirstRunDate: Date;
  let runOncePeriodicRunDate: Date;

  it('should on first run, execute new operations from the list', async () => {
    await dataSanityHandler();

    // Check run_once operation has been executed
    const runOnceOp = await findDataSanityByOperationName(testContext, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();
    expect(runOnceOp?.operation_name).toBe('mockRunOnceOperation');
    expect(runOnceOp?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(runOnceOp?.last_failure_message).toBe('');
    expect(runOnceOp?.force_run).toBe(false);
    if (runOnceOp?.last_run_date) {
      runOnceFirstRunDate = runOnceOp?.last_run_date;
    }

    // Check periodic operation has been executed
    const periodicOp = await findDataSanityByOperationName(testContext, 'mockRunPeriodicOperation');
    expect(periodicOp).toBeDefined();
    expect(periodicOp?.operation_name).toBe('mockRunPeriodicOperation');
    expect(periodicOp?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(periodicOp?.last_failure_message).toBe('');
    expect(periodicOp?.force_run).toBe(false);
    if (periodicOp?.last_run_date) {
      runOncePeriodicRunDate = periodicOp?.last_run_date;
    }

    // Check on_demand operation is registered but has NOT been executed (no meaningful run date)
    const onDemandOp = await findDataSanityByOperationName(testContext, 'mockRunOnDemandOperation');
    expect(onDemandOp).toBeDefined();
    expect(onDemandOp?.operation_name).toBe('mockRunOnDemandOperation');
    expect(onDemandOp?.last_execution_time).toBe(0);
    expect(onDemandOp?.last_failure_message).toBe('');
    expect(onDemandOp?.force_run).toBe(false);
  });

  it('should on second run, execute only periodic operations from the list', async () => {
    await dataSanityHandler();

    // Check run_once operation has NOT been re-executed
    const runOnceOp = await findDataSanityByOperationName(testContext, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();
    expect(runOnceOp?.last_run_date).toBe(runOnceFirstRunDate);

    // Check periodic operation has been executed again
    const periodicOp = await findDataSanityByOperationName(testContext, 'mockRunPeriodicOperation');
    expect(periodicOp).toBeDefined();
    expect(periodicOp?.last_run_date).not.toBe(runOncePeriodicRunDate);

    // Check on_demand operation is registered but has NOT been executed (no meaningful run date)
    const onDemandOp = await findDataSanityByOperationName(testContext, 'mockRunOnDemandOperation');
    expect(onDemandOp).toBeDefined();
    expect(onDemandOp?.operation_name).toBe('mockRunOnDemandOperation');
    expect(onDemandOp?.last_execution_time).toBe(0);
    expect(onDemandOp?.last_failure_message).toBe('');
    expect(onDemandOp?.force_run).toBe(false);
  });

  it('should run on demand be executed on one operation already run', async () => {
    // GIVEN a force run has been requested
    await setForceRun(testContext, ADMIN_USER, 'mockRunOnDemandOperation');

    const onDemandOp = await findDataSanityByOperationName(testContext, 'mockRunOnDemandOperation');
    expect(onDemandOp).toBeDefined();
    expect(onDemandOp?.operation_name).toBe('mockRunOnDemandOperation');
    expect(onDemandOp?.last_execution_time).toBe(0); // not run yet
    expect(onDemandOp?.force_run).toBe(true);// this mean it's planned

    // WHEN manager handler runs
    await dataSanityHandler();

    // THEN
    const onDemandOpAfterRun = await findDataSanityByOperationName(testContext, 'mockRunOnDemandOperation');
    expect(onDemandOpAfterRun).toBeDefined();
    expect(onDemandOpAfterRun?.operation_name).toBe('mockRunOnDemandOperation');
    expect(onDemandOpAfterRun?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(onDemandOpAfterRun?.last_failure_message).toBe('');
    expect(onDemandOpAfterRun?.force_run).toBe(false); // should be back to false
  });

  it('should run on demand be executed on one operation never run', async () => {
    // GIVEN a force run has been requested
    await setForceRun(testContext, ADMIN_USER, 'mockRunOnDemandOperation2');

    const onDemandOp = await findDataSanityByOperationName(testContext, 'mockRunOnDemandOperation2');
    expect(onDemandOp).toBeDefined();
    expect(onDemandOp?.operation_name).toBe('mockRunOnDemandOperation2');
    expect(onDemandOp?.last_execution_time).toBe(0); // not run yet
    expect(onDemandOp?.force_run).toBe(true);// this mean it's planned

    // WHEN manager handler runs
    await dataSanityHandler();

    // THEN
    const onDemandOpAfterRun = await findDataSanityByOperationName(testContext, 'mockRunOnDemandOperation2');
    expect(onDemandOpAfterRun).toBeDefined();
    expect(onDemandOpAfterRun?.operation_name).toBe('mockRunOnDemandOperation2');
    expect(onDemandOpAfterRun?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(onDemandOpAfterRun?.last_failure_message).toBe('');
    expect(onDemandOpAfterRun?.force_run).toBe(false); // should be back to false
  });

  it('should operation with error be managed', async () => {
    // GIVEN a force run has been requested
    await setForceRun(testContext, ADMIN_USER, 'mockRunOnceOperationThatFails');
    // WHEN manager handler runs, no error throw but it's store in database instead
    await dataSanityHandler();

    // THEN
    const onDemandOpAfterRun = await findDataSanityByOperationName(testContext, 'mockRunOnceOperationThatFails');
    expect(onDemandOpAfterRun).toBeDefined();
    expect(onDemandOpAfterRun?.operation_name).toBe('mockRunOnceOperationThatFails');
    expect(onDemandOpAfterRun?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(onDemandOpAfterRun?.last_failure_message).toBe('This is raising error - mockRunOnceOperationThatFails');
    expect(onDemandOpAfterRun?.force_run).toBe(false); // should be back to false
  });
});
