import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as sanityManagerConfigMock from '../../../../src/modules/dataSanity/dataSanity-operations';
import { dataSanityHandler } from '../../../../src/manager/dataSanityManager';
import { findDataSanityByOperationName, markOperationAsRunning, OPERATION_STOPPED_MESSAGE, setForceRun, stopOperation } from '../../../../src/modules/dataSanity/dataSanity-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import convertDataSanityToStix from '../../../../src/modules/dataSanity/dataSanity-converter';
import type { StoreEntityDataSanity } from '../../../../src/modules/dataSanity/dataSanity-types';
import { ENTITY_TYPE_DATA_SANITY_EXECUTION } from '../../../../src/modules/dataSanity/dataSanity-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { updateAttribute } from '../../../../src/database/middleware';
import { utcDate } from '../../../../src/utils/format';

describe('Data sanity manager handler test coverage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(sanityManagerConfigMock, 'sanityOperationList').mockReturnValue([
      {
        identifier: 'mockRunOnceOperation',
        dryRun: async () => {
          return { impact: { total: 2, detail: { Malware: 2 } } };
        },
        operationRun: async () => {
          return { impact: { total: 2, detail: { Malware: 2 } } };
        },
        execution_type: 'run_once',
        description: '',
        display_name: '',
        eligibleEntityTypes: [ENTITY_TYPE_MALWARE],
      }, {
        identifier: 'mockRunOnceOperationThatFails',
        dryRun: async () => {
          return { impact: { total: 2, detail: { Malware: 2 } } };
        },
        operationRun: async () => {
          throw Error('This is raising error - mockRunOnceOperationThatFails');
        },
        execution_type: 'run_once',
        description: '',
        display_name: '',
        eligibleEntityTypes: [ENTITY_TYPE_MALWARE],
      },
    ]);
  });

  let runOnceFirstRunDate: Date;

  it('should on first run, execute new operations from the list', async () => {
    await dataSanityHandler();

    // Check run_once operation has been executed
    const runOnceOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();
    expect(runOnceOp?.operation_name).toBe('mockRunOnceOperation');
    expect(runOnceOp?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(runOnceOp?.last_run_success).toBe(true);
    expect(runOnceOp?.force_run).toBe(false);
    if (runOnceOp?.last_run_date) {
      runOnceFirstRunDate = runOnceOp?.last_run_date;
    }
  });

  it('should on second run, not execute run once operations from the list', async () => {
    await dataSanityHandler();

    // Check run_once operation has NOT been re-executed
    const runOnceOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();
    expect(runOnceOp?.last_run_date).toBe(runOnceFirstRunDate);
  });

  it('should force run of a run once script work', async () => {
    await setForceRun(testContext, ADMIN_USER, 'mockRunOnceOperation');
    const runOnceOpBefore = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockRunOnceOperation');
    expect(runOnceOpBefore).toBeDefined();
    expect(runOnceOpBefore?.force_run).toBeTruthy();

    await dataSanityHandler();

    // Check run_once operation has been re-executed on demand
    const runOnceOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();
    expect(runOnceOp?.force_run).toBeFalsy();
    expect(runOnceOp?.last_run_date).toBeDefined();
    expect(new Date(runOnceOp!.last_run_date).getTime()).toBeGreaterThan(new Date(runOnceFirstRunDate).getTime());
  });

  it('should operation with error be managed', async () => {
    // GIVEN a force run has been requested
    await setForceRun(testContext, ADMIN_USER, 'mockRunOnceOperationThatFails');
    // WHEN manager handler runs, no error throw but it's store in database instead
    await dataSanityHandler();

    // THEN
    const onDemandOpAfterRun = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockRunOnceOperationThatFails');
    expect(onDemandOpAfterRun).toBeDefined();
    expect(onDemandOpAfterRun?.operation_name).toBe('mockRunOnceOperationThatFails');
    expect(onDemandOpAfterRun?.last_execution_time).toBeGreaterThanOrEqual(0);
    expect(onDemandOpAfterRun?.last_run_message).toBe('This is raising error - mockRunOnceOperationThatFails');
    expect(onDemandOpAfterRun?.force_run).toBe(false); // should be back to false
  });

  it('should not execute an operation already marked as running', async () => {
    const operationRun = vi.fn(async () => ({ impact: { total: 1, detail: { Malware: 1 } } }));
    vi.mocked(sanityManagerConfigMock.sanityOperationList).mockReturnValue([
      {
        identifier: 'mockAlreadyRunningOperation',
        dryRun: async () => ({ impact: { total: 1, detail: { Malware: 1 } } }),
        operationRun,
        execution_type: 'run_once',
        description: '',
        display_name: '',
        eligibleEntityTypes: [ENTITY_TYPE_MALWARE],
      },
    ]);

    await markOperationAsRunning(testContext, ADMIN_USER, 'mockAlreadyRunningOperation');
    await dataSanityHandler();

    expect(operationRun).not.toHaveBeenCalled();
    const runningOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockAlreadyRunningOperation');
    expect(runningOp?.is_running).toBe(true);
  });

  it('should not execute a force_run operation already marked as running', async () => {
    const operationRun = vi.fn(async () => ({ impact: { total: 1, detail: { Malware: 1 } } }));
    vi.mocked(sanityManagerConfigMock.sanityOperationList).mockReturnValue([
      {
        identifier: 'mockForceRunWhileRunningOperation',
        dryRun: async () => ({ impact: { total: 1, detail: { Malware: 1 } } }),
        operationRun,
        execution_type: 'run_once',
        description: '',
        display_name: '',
        eligibleEntityTypes: [ENTITY_TYPE_MALWARE],
      },
    ]);

    // GIVEN an operation currently running for which a force run is requested
    await markOperationAsRunning(testContext, ADMIN_USER, 'mockForceRunWhileRunningOperation');
    await setForceRun(testContext, ADMIN_USER, 'mockForceRunWhileRunningOperation');

    // WHEN the scheduler runs
    await dataSanityHandler();

    // THEN no concurrent execution is started and the running lock/force_run flag are preserved
    expect(operationRun).not.toHaveBeenCalled();
    const runningOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockForceRunWhileRunningOperation');
    expect(runningOp?.is_running).toBe(true);
    expect(runningOp?.force_run).toBe(true);
  });

  it('should execute an operation whose running lock is stale (last_run_date older than threshold)', async () => {
    const operationRun = vi.fn(async () => ({ impact: { total: 1, detail: { Malware: 1 } } }));
    vi.mocked(sanityManagerConfigMock.sanityOperationList).mockReturnValue([
      {
        identifier: 'mockStaleRunningOperation',
        dryRun: async () => ({ impact: { total: 1, detail: { Malware: 1 } } }),
        operationRun,
        execution_type: 'run_once',
        description: 'Operation that become stale',
        display_name: 'stale-op',
        eligibleEntityTypes: [ENTITY_TYPE_MALWARE],
      },
    ]);

    // GIVEN an operation stuck as running since 25 hours ago (simulating a crashed node)
    await markOperationAsRunning(testContext, ADMIN_USER, 'mockStaleRunningOperation');
    const staleEntity = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockStaleRunningOperation');
    const twentyFiveHoursAgo = utcDate().subtract(25, 'hours').toISOString();
    await updateAttribute(testContext, ADMIN_USER, staleEntity!.internal_id, ENTITY_TYPE_DATA_SANITY_EXECUTION, [
      { key: 'last_run_date', value: [twentyFiveHoursAgo] },
    ]);

    // WHEN the scheduler runs
    await dataSanityHandler();

    // THEN the stale operation is executed again and the lock is released
    expect(operationRun).toHaveBeenCalledTimes(1);
    const executedOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockStaleRunningOperation');
    expect(executedOp?.is_running).toBe(false);
    expect(executedOp?.last_run_success).toBe(true);
  });

  it('should mark a running operation as done when it is stopped, and allow to run it again', async () => {
    const operationRun = vi.fn(async () => ({ impact: { total: 1, detail: { Malware: 1 } } }));
    vi.mocked(sanityManagerConfigMock.sanityOperationList).mockReturnValue([
      {
        identifier: 'mockStoppedOperation',
        dryRun: async () => ({ impact: { total: 1, detail: { Malware: 1 } } }),
        operationRun,
        execution_type: 'run_once',
        description: 'Operation that gets stopped manually',
        display_name: 'stopped-op',
        eligibleEntityTypes: [ENTITY_TYPE_MALWARE],
      },
    ]);

    // GIVEN an operation currently running with a pending force run
    await markOperationAsRunning(testContext, ADMIN_USER, 'mockStoppedOperation');
    await setForceRun(testContext, ADMIN_USER, 'mockStoppedOperation');

    // WHEN it is stopped
    await stopOperation(testContext, ADMIN_USER, 'mockStoppedOperation');

    // THEN it is marked as done: no running lock, no pending force run
    const stoppedOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockStoppedOperation');
    expect(stoppedOp?.is_running).toBe(false);
    expect(stoppedOp?.force_run).toBe(false);
    expect(stoppedOp?.last_run_success).toBe(false);
    expect(stoppedOp?.last_run_message).toBe(OPERATION_STOPPED_MESSAGE);

    // AND the scheduler does not re-execute it by itself (already executed)
    await dataSanityHandler();
    expect(operationRun).not.toHaveBeenCalled();

    // AND it can be triggered again through a force run
    await setForceRun(testContext, ADMIN_USER, 'mockStoppedOperation');
    await dataSanityHandler();
    expect(operationRun).toHaveBeenCalledTimes(1);
    const reRunOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockStoppedOperation');
    expect(reRunOp?.is_running).toBe(false);
    expect(reRunOp?.force_run).toBe(false);
    expect(reRunOp?.last_run_success).toBe(true);
  });

  it('should throw an error when stopping an unknown operation', async () => {
    await expect(stopOperation(testContext, ADMIN_USER, 'mockUnknownOperation'))
      .rejects.toThrowError('Unknown sanity operation: mockUnknownOperation');
  });

  it('should convert a DataSanity entity to STIX format', async () => {
    const runOnceOp = await findDataSanityByOperationName(testContext, ADMIN_USER, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();

    const result = convertDataSanityToStix(runOnceOp as StoreEntityDataSanity);

    // Core STIX properties
    expect(result.type).toBe('datasanityexecution');
    expect(result.id).toBeDefined();

    // All domain-specific fields are mapped correctly
    expect(result.operation_name).toBe('mockRunOnceOperation');
    expect(result.last_run_date).toBe(runOnceOp!.last_run_date);
    expect(result.last_execution_time).toBe(runOnceOp!.last_execution_time);
    expect(result.last_run_success).toBe(true);
    expect(result.last_run_message).toBeDefined();
    expect(result.last_run_output).toBeDefined();

    // STIX extension structure
    expect(result.extensions).toBeDefined();
    expect(result.extensions[STIX_EXT_OCTI]).toBeDefined();
    expect(result.extensions[STIX_EXT_OCTI].extension_type).toBe('new-sdo');
  });
});
