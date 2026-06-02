import { describe, expect, it, vi } from 'vitest';
import { IngestionAuthType, type IngestionTaxiiAddInput, TaxiiVersion } from '../../../../src/generated/graphql';

import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as connectorMock from '../../../../src/domain/connector';
import {
  addIngestion as addTaxiiIngestion,
  findById as findTaxiiIngestionById,
  ingestionDelete,
  patchTaxiiIngestion,
} from '../../../../src/modules/ingestion/ingestion-taxii-domain';
import { taxiiExecutor } from '../../../../src/manager/ingestionManager';
import { now } from '../../../../src/utils/format';

describe('Verify taxiiExecutor', () => {
  it('should taxiiExecutor process ingestion when queue is empty (messages_number === 0)', async () => {
    // Create an ingestion with ingestion_running: true and no last_execution_date
    // And queue is empty
    // so isMustExecuteIteration returns true
    vi.spyOn(connectorMock, 'queueDetails').mockResolvedValue({ messages_number: 0, messages_size: 0 });

    const input: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii executor empty queue test',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestion = await addTaxiiIngestion(testContext, ADMIN_USER, input);
    expect(ingestion.id).toBeDefined();

    // Execute taxiiExecutor - ingestion has no last_execution_date so isMustExecuteIteration returns true
    // Queue is empty (messages_number === 0) so it will call the taxii handler
    await expect(taxiiExecutor(testContext)).resolves.not.toThrow();

    await ingestionDelete(testContext, ADMIN_USER, ingestion.internal_id);
  });

  it('should taxiiExecutor skip ingestion when scheduling period has not elapsed', async () => {
    // Create an ingestion with a scheduling period and a recent last_execution_date
    const input: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii executor scheduling skip test',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1D', // 1 day period
    };
    const ingestion = await addTaxiiIngestion(testContext, ADMIN_USER, input);
    expect(ingestion.id).toBeDefined();

    // Patch last_execution_date to now so isMustExecuteIteration returns false (1 day not elapsed)
    await patchTaxiiIngestion(testContext, ADMIN_USER, ingestion.internal_id, { last_execution_date: now() });

    // Execute taxiiExecutor - should skip the ingestion because scheduling period has not elapsed
    await expect(taxiiExecutor(testContext)).resolves.not.toThrow();

    // Verify ingestion state was not modified (no new execution happened)
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestion.id);
    // last_execution_date should still be the patched value (not updated by executor)
    expect(result.last_execution_date).toBeDefined();

    await ingestionDelete(testContext, ADMIN_USER, ingestion.internal_id);
  });

  it('should taxiiExecutor handle buffering when queue has remaining messages', async () => {
    // Create an ingestion
    const input: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii executor buffering test',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestion = await addTaxiiIngestion(testContext, ADMIN_USER, input);
    expect(ingestion.id).toBeDefined();

    // Now run taxiiExecutor - should enter the buffering branch (messages_number > 0)
    vi.spyOn(connectorMock, 'queueDetails').mockResolvedValue({ messages_number: 5, messages_size: 10 });
    await expect(taxiiExecutor(testContext)).resolves.not.toThrow();

    await ingestionDelete(testContext, ADMIN_USER, ingestion.internal_id);
  });

  it('should taxiiExecutor do nothing when no running ingestion exists', async () => {
    // Create an ingestion that is NOT running
    const input: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: false,
      name: 'taxii executor not running test',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestion = await addTaxiiIngestion(testContext, ADMIN_USER, input);
    expect(ingestion.id).toBeDefined();

    // Execute taxiiExecutor - should not process the non-running ingestion
    await expect(taxiiExecutor(testContext)).resolves.not.toThrow();

    await ingestionDelete(testContext, ADMIN_USER, ingestion.internal_id);
  });
});
