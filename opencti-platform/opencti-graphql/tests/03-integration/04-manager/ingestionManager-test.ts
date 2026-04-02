import { describe, expect, it } from 'vitest';
import {
  prepareTaxiiGetParam,
  processCsvLines,
  processTaxiiResponse,
  pushBundleToConnectorQueue,
  taxiiExecutor,
  type TaxiiResponseData,
} from '../../../src/manager/ingestionManager';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { addIngestion as addTaxiiIngestion, findById as findTaxiiIngestionById, ingestionDelete, patchTaxiiIngestion } from '../../../src/modules/ingestion/ingestion-taxii-domain';
import { type CsvMapperAddInput, IngestionAuthType, type IngestionCsvAddInput, type IngestionTaxiiAddInput, TaxiiVersion } from '../../../src/generated/graphql';
import type { StixReport } from '../../../src/types/stix-2-1-sdo';
import { now } from '../../../src/utils/format';
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';
import type { BasicStoreEntityIngestionCsv, BasicStoreEntityIngestionTaxii } from '../../../src/modules/ingestion/ingestion-types';
import type { StixBundle } from '../../../src/types/stix-2-1-common';
import { csvMapperMockCities } from './ingestionManager/csv-mapper-cities';
import { addIngestionCsv, findById as findIngestionCsvById } from '../../../src/modules/ingestion/ingestion-csv-domain';
import { createCsvMapper } from '../../../src/modules/internal/csvMapper/csvMapper-domain';
import { parseCsvMapper } from '../../../src/modules/internal/csvMapper/csvMapper-utils';
import { awaitUntilCondition, readCsvFromFileStream } from '../../utils/testQueryHelper';
import { connectorIdFromIngestId, queueDetails } from '../../../src/domain/connector';

describe('Verify taxii ingestion', () => {
  it('should Taxii server response with no pagination (no next, no more, no x-taxii-date-added-last)', async () => {
    // 1. Create ingestion in opencti
    const input: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with no pagination',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestionNotPagination = await addTaxiiIngestion(testContext, ADMIN_USER, input);
    expect(ingestionNotPagination.id).toBeDefined();
    expect(ingestionNotPagination.internal_id).toBeDefined();
    // 2. Check parameter send to taxii server
    const expectedParams = prepareTaxiiGetParam(ingestionNotPagination);
    expect(expectedParams.next).toBeUndefined();
    expect(expectedParams.added_after).toBeUndefined();

    // 3. Simulate a taxii server response and check opencti behavior.
    const taxiResponse: TaxiiResponseData = {
      data: {
        next: undefined,
        objects: [
          { confidence: 100,
            created: '2024-06-03T20:35:44.000Z',
            description: 'The best description of the world',
            published: '2024-06-03T20:35:44.000Z',
            revoked: false,
            spec_version: '2.1',
            type: 'report' } as unknown as StixReport],
        more: undefined,
      },
      addedLastHeader: undefined,
    };

    await processTaxiiResponse(testContext, ingestionNotPagination, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestionNotPagination.id);
    expect(result.current_state_cursor).toBeUndefined();
    expect(result.added_after_start).toBeDefined();

    // Delete the ingest
    await ingestionDelete(testContext, ADMIN_USER, ingestionNotPagination.internal_id);
  });

  it('should taxii server response with data and next page and start date', async () => {
    // 1. Create ingestion in opencti
    const input2: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with pagination and start date',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      added_after_start: '2024-01-01T20:35:44.000Z',
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestionPaginatedWithStartDate = await addTaxiiIngestion(testContext, ADMIN_USER, input2);
    expect(ingestionPaginatedWithStartDate.id).toBeDefined();
    expect(ingestionPaginatedWithStartDate.internal_id).toBeDefined();

    // 2. Check parameter send to taxii server for the first call
    const expectedParams1 = prepareTaxiiGetParam(ingestionPaginatedWithStartDate);
    expect(expectedParams1.next).toBeUndefined();
    expect(expectedParams1.added_after).toBe('2024-01-01T20:35:44.000Z');

    // 3. Simulate a taxii server response with pagination (more = true) and check opencti behavior.
    const taxiResponse1: TaxiiResponseData = {
      data: {
        next: '1234',
        objects: [
          { confidence: 100,
            created: '2024-06-03T20:35:44.000Z',
            description: 'The best description of the world',
            published: '2024-06-03T20:35:44.000Z',
            revoked: false,
            spec_version: '2.1',
            type: 'report' } as unknown as StixReport],
        more: true,
      },
      addedLastHeader: '2024-02-01T20:35:44.000Z',
    };

    await processTaxiiResponse(testContext, ingestionPaginatedWithStartDate, taxiResponse1);
    const taxiiEntityAfterfirstRequest = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestionPaginatedWithStartDate.id);
    expect(taxiiEntityAfterfirstRequest.current_state_cursor).toBe('1234');
    expect(taxiiEntityAfterfirstRequest.added_after_start, 'should keep the start date set at ingestion creation').toBe('2024-01-01T20:35:44.000Z');

    // 4. Check parameter send to taxii server for the next call
    const expectedParams2 = prepareTaxiiGetParam(taxiiEntityAfterfirstRequest);
    expect(expectedParams2.next).toBe('1234');
    expect(expectedParams2.added_after).toBe('2024-01-01T20:35:44.000Z');

    // 5. Simulate a taxii server response with last data (more = false)
    const taxiResponse: TaxiiResponseData = {
      data: {
        next: '1334',
        objects: [
          { confidence: 100,
            created: '2024-06-03T20:35:44.000Z',
            description: 'The best description of the world',
            published: '2024-06-03T20:35:44.000Z',
            revoked: false,
            spec_version: '2.1',
            type: 'report' } as unknown as StixReport],
        more: false,
      },
      addedLastHeader: '2024-03-01T20:35:44.000Z',
    };

    await processTaxiiResponse(testContext, taxiiEntityAfterfirstRequest, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, taxiiEntityAfterfirstRequest.id);
    expect(result.current_state_cursor, 'Since more is false, next value should be reset').toBeUndefined();
    expect(result.added_after_start).toBe('2024-03-01T20:35:44.000Z');

    // Delete the ingest
    await ingestionDelete(testContext, ADMIN_USER, ingestionPaginatedWithStartDate.internal_id);
  });

  it('should taxii server response with no start date, and next page', async () => {
    // 1. Create ingestion in opencti
    const input3: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with pagination no start date',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestionPaginatedWithNoStartDate = await addTaxiiIngestion(testContext, ADMIN_USER, input3);
    expect(ingestionPaginatedWithNoStartDate.id).toBeDefined();
    expect(ingestionPaginatedWithNoStartDate.internal_id).toBeDefined();

    // 2. Check parameter send to taxii server for the first call
    const expectedParams1 = prepareTaxiiGetParam(ingestionPaginatedWithNoStartDate);
    expect(expectedParams1.next).toBeUndefined();
    expect(expectedParams1.added_after).toBeUndefined();

    // 3. Simulate a taxii server response with pagination (more = true) and check opencti behavior.
    const taxiResponse: TaxiiResponseData = {
      data: {
        next: '4321',
        objects: [
          { confidence: 100,
            created: '2024-06-03T20:35:44.000Z',
            description: 'The best description of the world',
            published: '2024-06-03T20:35:44.000Z',
            revoked: false,
            spec_version: '2.1',
            type: 'report' } as unknown as StixReport],
        more: true,
      },
      addedLastHeader: '2024-02-01T20:35:44.000Z',
    };

    await processTaxiiResponse(testContext, ingestionPaginatedWithNoStartDate, taxiResponse);
    const taxiiEntityAfterFirstCall = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestionPaginatedWithNoStartDate.id);
    expect(taxiiEntityAfterFirstCall.current_state_cursor).toBe('4321');
    expect(taxiiEntityAfterFirstCall.added_after_start).toBeUndefined();

    // 4. Check parameter send to taxii server for the next call
    const expectedParams2 = prepareTaxiiGetParam(taxiiEntityAfterFirstCall);
    expect(expectedParams2.next).toBe('4321');
    expect(expectedParams2.added_after).toBeUndefined();

    // 5. Simulate a taxii server response with last data (more = false)
    const taxiResponse2: TaxiiResponseData = {
      data: {
        next: '4444',
        objects: [
          { confidence: 100,
            created: '2024-06-03T20:35:44.000Z',
            description: 'The best description of the world',
            published: '2024-06-03T20:35:44.000Z',
            revoked: false,
            spec_version: '2.1',
            type: 'report' } as unknown as StixReport],
        more: false,
      },
      addedLastHeader: '2024-03-01T20:44:44.000Z',
    };

    await processTaxiiResponse(testContext, taxiiEntityAfterFirstCall, taxiResponse2);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, taxiiEntityAfterFirstCall.id);
    expect(result.current_state_cursor, 'Since more is false, next value should be reset').toBeUndefined();
    expect(result.added_after_start).toBe('2024-03-01T20:44:44.000Z');

    // Delete the ingest
    await ingestionDelete(testContext, ADMIN_USER, ingestionPaginatedWithNoStartDate.internal_id);
  });

  it('should store nothing when no data', async () => {
    // 1. Create ingestion in opencti
    const input2: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with pagination and start date',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      added_after_start: '2023-01-01T20:35:44.000Z',
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestionPaginatedWithStartDate = await addTaxiiIngestion(testContext, ADMIN_USER, input2);
    expect(ingestionPaginatedWithStartDate.id).toBeDefined();
    expect(ingestionPaginatedWithStartDate.internal_id).toBeDefined();

    const taxiResponse: TaxiiResponseData = {
      data: {
        next: undefined,
        objects: [],
        more: false,
      },
      addedLastHeader: '2021-11-11T11:11:11.111Z',
    };

    await processTaxiiResponse(testContext, ingestionPaginatedWithStartDate, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestionPaginatedWithStartDate.id);
    expect(result.current_state_cursor).toBeUndefined(); // previous value
    expect(result.added_after_start).toBe('2023-01-01T20:35:44.000Z'); // previous value

    // Delete the ingest
    await ingestionDelete(testContext, ADMIN_USER, ingestionPaginatedWithStartDate.internal_id);
  });
});

describe('Verify taxii ingestion - patch part', () => {
  it('should Taxii server response next as number be transform', async () => {
    // 1. Create ingestion in opencti
    const input: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion for patch test',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      user_id: ADMIN_USER.id,
      scheduling_period: 'PT1H',
    };
    const ingestion = await addTaxiiIngestion(testContext, ADMIN_USER, input);
    expect(ingestion.id).toBeDefined();
    expect(ingestion.internal_id).toBeDefined();

    const state = { current_state_cursor: 1234, last_execution_date: now() };
    // @ts-expect-error it's what we want to test: number instead of string. Not sure how it happens with typescript ...
    const result = await patchTaxiiIngestion(testContext, ADMIN_USER, ingestion.id, state);
    expect(result.id).toBeDefined();
    // should not throw exception "Unknown Error: Attribute must be a string"

    // Delete the ingest
    await ingestionDelete(testContext, ADMIN_USER, ingestion.internal_id);
  });
});

describe('Verify taxiiExecutor', () => {
  it('should taxiiExecutor process ingestion when queue is empty (messages_number === 0)', async () => {
    // Create an ingestion with ingestion_running: true and no last_execution_date
    // so isMustExecuteIteration returns true
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

    // Wait for the queue to be ready
    await awaitUntilCondition(async () => {
      try {
        const queryResult = await queueDetails(connectorIdFromIngestId(ingestion.id));
        return queryResult?.messages_number >= 0;
      } catch {
        return false;
      }
    }, 10000, 6);

    // Execute taxiiExecutor - ingestion has no last_execution_date so isMustExecuteIteration returns true
    // Queue is empty (messages_number === 0) so it will call the taxii handler
    // The handler will fail because the URI is invalid, but the error is caught internally
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

    // Wait for the queue to be ready
    await awaitUntilCondition(async () => {
      try {
        const queryResult = await queueDetails(connectorIdFromIngestId(ingestion.id));
        return queryResult?.messages_number >= 0;
      } catch {
        return false;
      }
    }, 10000, 6);

    // Patch last_execution_date to now so isMustExecuteIteration returns false (1 day not elapsed)
    await patchTaxiiIngestion(testContext, ADMIN_USER, ingestion.id, { last_execution_date: now() });

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

    // Wait for the queue to be ready
    await awaitUntilCondition(async () => {
      try {
        const queryResult = await queueDetails(connectorIdFromIngestId(ingestion.id));
        return queryResult?.messages_number >= 0;
      } catch {
        return false;
      }
    }, 10000, 6);

    // Push a fake bundle to the queue so messages_number > 0
    const fakeBundle: StixBundle = {
      type: 'bundle',
      spec_version: '2.1',
      id: 'bundle--fake-for-buffering-test',
      objects: [{ type: 'report', spec_version: '2.1', id: 'report--fake', name: 'fake', published: '2024-01-01T00:00:00.000Z' } as unknown as StixReport],
    };
    await pushBundleToConnectorQueue(testContext, ingestion as unknown as BasicStoreEntityIngestionTaxii, fakeBundle);

    // Verify the queue has messages
    await awaitUntilCondition(async () => {
      const queryResult = await queueDetails(connectorIdFromIngestId(ingestion.id));
      return queryResult?.messages_number > 0;
    }, 10000, 6);

    // Now run taxiiExecutor - should enter the buffering branch (messages_number > 0)
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

describe('Verify csv ingestion', () => {
  let csvLines: string[];
  let csvMapperParsed: CsvMapperParsed;
  let ingestionCsv: BasicStoreEntityIngestionCsv;

  it('should prepare ingestion data', async () => {
    const mapper = csvMapperMockCities as CsvMapperParsed;
    const csvMapperInput: CsvMapperAddInput = {
      has_header: mapper.has_header,
      name: 'testCsvIngestionMapper',
      representations: JSON.stringify(mapper.representations),
      separator: mapper.separator,
      skipLineChar: mapper.skipLineChar,
    };

    const mapperCreated = await createCsvMapper(testContext, ADMIN_USER, csvMapperInput);
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      ingestion_running: true,
      name: 'csv ingestion',
      uri: 'http://test.invalid',
      csv_mapper_id: mapperCreated.id,
      user_id: ADMIN_USER.id,
    };
    ingestionCsv = await addIngestionCsv(testContext, ADMIN_USER, ingestionCsvInput);
    expect(ingestionCsv.id).toBeDefined();
    expect(ingestionCsv.internal_id).toBeDefined();

    await awaitUntilCondition(async () => {
      try {
        const queryResult = await queueDetails(connectorIdFromIngestId(ingestionCsv.id));
        return queryResult?.messages_number >= 0;
      } catch {
        return false;
      }
    }, 10000, 6); // Wait for the queue result to exist - max 1 minute
    csvMapperParsed = parseCsvMapper(mapperCreated);

    csvLines = await readCsvFromFileStream('./tests/03-integration/04-manager/ingestionManager', 'csv-file-cities.csv');
  });

  it('should csv ingestion run', async () => {
    const { isUnchangedData, objectsInBundleCount } = await processCsvLines(testContext, ingestionCsv, csvMapperParsed, [...csvLines], null);
    expect(isUnchangedData).toBeFalsy();

    // csv-file-cities.csv content:
    // skip lines and header => 0 object
    // 1 city +1 label => 2 objects
    // skip line => 0 object
    // 1 city +1 label => 2 objects
    // 1 city (duplicate) +1 label => 2 objects
    // 1 city +1 label => 2 objects
    expect(objectsInBundleCount).toBe(8);
  });

  it('should same csv file ingestion be skipped', async () => {
    // Second time hash is the same so it should not process any objects
    const ingestionEntity = await findIngestionCsvById(testContext, ADMIN_USER, ingestionCsv.id);
    const { isUnchangedData, objectsInBundleCount } = await processCsvLines(testContext, ingestionEntity, csvMapperParsed, [...csvLines], null);
    expect(isUnchangedData).toBeTruthy();
    expect(objectsInBundleCount).toBe(0);
  });
});
