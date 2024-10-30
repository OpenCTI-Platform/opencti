import { describe, expect, it } from 'vitest';
import * as readline from 'node:readline';
import { prepareTaxiiGetParam, processCsvLines, processTaxiiResponse, type TaxiiResponseData } from '../../../src/manager/ingestionManager';
import { addIngestion as addTaxiiIngestion, findById as findTaxiiIngestionById, ingestionDelete, patchTaxiiIngestion } from '../../../src/modules/ingestion/ingestion-taxii-domain';
import { type CsvMapperAddInput, IngestionAuthType, type IngestionCsvAddInput, type IngestionTaxiiAddInput, TaxiiVersion } from '../../../src/generated/graphql';
import type { StixReport } from '../../../src/types/stix-sdo';
import { now } from '../../../src/utils/format';
import { createCsvMapper } from '../../../src/modules/internal/csvMapper/csvMapper-domain';
import { parseCsvMapper } from '../../../src/modules/internal/csvMapper/csvMapper-utils';
import { csvMapperMockSimpleCities } from '../../data/importCsv-connector/csv-mapper-cities';
import { fileToReadStream } from '../../../src/database/file-storage-helper';

describe('Verify taxii ingestion', () => {
  it('should Taxii server response with no pagination (no next, no more, no x-taxii-date-added-last)', async () => {
    // 1. Create ingestion in opencti
    const input : IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with no pagination',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
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
        more: undefined
      },
      addedLastHeader: undefined
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
    const input2 : IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with pagination and start date',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      added_after_start: '2024-01-01T20:35:44.000Z'
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
        more: true
      },
      addedLastHeader: '2024-02-01T20:35:44.000Z'
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
        more: false
      },
      addedLastHeader: '2024-03-01T20:35:44.000Z'
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
    const input3 : IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with pagination no start date',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
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
        more: true
      },
      addedLastHeader: '2024-02-01T20:35:44.000Z'
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
        more: false
      },
      addedLastHeader: '2024-03-01T20:44:44.000Z'
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
    const input2 : IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion with pagination and start date',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
      added_after_start: '2023-01-01T20:35:44.000Z'
    };
    const ingestionPaginatedWithStartDate = await addTaxiiIngestion(testContext, ADMIN_USER, input2);
    expect(ingestionPaginatedWithStartDate.id).toBeDefined();
    expect(ingestionPaginatedWithStartDate.internal_id).toBeDefined();

    const taxiResponse: TaxiiResponseData = {
      data: {
        next: undefined,
        objects: [],
        more: false
      },
      addedLastHeader: '2021-11-11T11:11:11.111Z'
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
    const input : IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion for patch test',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
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

    const csvLines: string[] = [];
    // Need an async interator to prevent blocking
    // eslint-disable-next-line no-restricted-syntax
    for await (const line of rl) {
      csvLines.push(line);
    }
    const csvLinesClone = [...csvLines];
    await processCsvLines(testContext, ingestionCsv, csvMapperParsed, csvLines, null);

    const ingestionCsvafterFirstProcess = await findIngestionCsvById(testContext, ADMIN_USER, ingestionCsv.id);

    // Second time hash is the same so it should not process any objects
    await processCsvLines(testContext, ingestionCsvafterFirstProcess, csvMapperParsed, csvLinesClone, null);
    const ingestionCsvafterSecondProcess = await findIngestionCsvById(testContext, ADMIN_USER, ingestionCsvafterFirstProcess.id);

    expect(ingestionCsvafterFirstProcess.current_state_hash).toBe(ingestionCsvafterSecondProcess.current_state_hash);

    // Not much to expect, no exception at least.
  });
});
