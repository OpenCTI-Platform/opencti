import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as sanityManagerConfigMock from '../../../../src/modules/dataSanity/dataSanity-operations';
import { dataSanityHandler } from '../../../../src/manager/dataSanityManager';
import { findDataSanityByOperationName, setForceRun } from '../../../../src/modules/dataSanity/dataSanity-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { getDataSanityConfigurationFromDatabase } from '../../../../src/modules/dataSanity/dataSanityConfiguration-domain';
import convertDataSanityConfigurationToStix from '../../../../src/modules/dataSanity/dataSanityConfiguration-converter';
import type { StoreEntityDataSanityConfiguration } from '../../../../src/modules/dataSanity/dataSanityConfiguration-types';
import convertDataSanityToStix from '../../../../src/modules/dataSanity/dataSanity-converter';
import type { StoreEntityDataSanity } from '../../../../src/modules/dataSanity/dataSanity-types';

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
    const runOnceOp = await findDataSanityByOperationName(testContext, 'mockRunOnceOperation');
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
    const runOnceOp = await findDataSanityByOperationName(testContext, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();
    expect(runOnceOp?.last_run_date).toBe(runOnceFirstRunDate);
  });

  it('should force run of a run once script work', async () => {
    await setForceRun(testContext, ADMIN_USER, 'mockRunOnceOperation');
    const runOnceOpBefore = await findDataSanityByOperationName(testContext, 'mockRunOnceOperation');
    expect(runOnceOpBefore).toBeDefined();
    expect(runOnceOpBefore?.force_run).toBeTruthy();

    await dataSanityHandler();

    // Check run_once operation has NOT been re-executed
    const runOnceOp = await findDataSanityByOperationName(testContext, 'mockRunOnceOperation');
    expect(runOnceOp).toBeDefined();
    expect(runOnceOpBefore?.force_run).toBeFalsy();
    expect(runOnceOp?.last_run_date.getTime()).toBeGreaterThan(runOnceFirstRunDate.getTime());
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
    expect(onDemandOpAfterRun?.last_run_message).toBe('This is raising error - mockRunOnceOperationThatFails');
    expect(onDemandOpAfterRun?.force_run).toBe(false); // should be back to false
  });

  it('should stix conversion works', async () => {
    const runOnceOp = await findDataSanityByOperationName(testContext, 'mockRunOnceOperation');
    if (runOnceOp) {
      const result = convertDataSanityToStix(runOnceOp as StoreEntityDataSanity);
      expect(result.operation_name).toBe('mockRunOnceOperation');
      expect(result.type).toBe('run_once');
    }
  });
});
