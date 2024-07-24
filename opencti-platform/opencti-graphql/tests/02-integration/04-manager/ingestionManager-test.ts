import { describe, expect, it } from 'vitest';
import { processTaxiiResponse, type TaxiiResponseData } from '../../../src/manager/ingestionManager';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { addIngestion as addTaxiiIngestion, findById as findTaxiiIngestionById } from '../../../src/modules/ingestion/ingestion-taxii-domain';
import { IngestionAuthType, type IngestionTaxiiAddInput, TaxiiVersion } from '../../../src/generated/graphql';
import type { BasicStoreEntityIngestionTaxii } from '../../../src/modules/ingestion/ingestion-types';

describe('Verify taxii ingestion', () => {
  let ingestion: BasicStoreEntityIngestionTaxii;

  it('should create a new ingestion', async () => {
    const input : IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testcollection',
      ingestion_running: true,
      name: 'taxii ingestion to test manager',
      uri: 'http://test.invalid',
      version: TaxiiVersion.V21,
    };
    ingestion = await addTaxiiIngestion(testContext, ADMIN_USER, input);
  });

  it('should Taxii server response with no pagination (no next, no more, no x-taxii-date-added-last)', async () => {
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
            type: 'report' }],
        more: undefined
      },
      addedLastHeader: undefined
    };

    await processTaxiiResponse(testContext, ingestion, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestion.id);
    expect(result.current_state_cursor).toBeUndefined();
    expect(result.taxii_more).toBeUndefined();
    expect(result.added_after_start).toBeUndefined();
  });

  it('should taxii server response with data and only next', async () => {
    const taxiResponse: TaxiiResponseData = {
      data: {
        next: '1234',
        objects: [
          { confidence: 100,
            created: '2024-06-03T20:35:44.000Z',
            description: 'The best description of the world',
            published: '2024-06-03T20:35:44.000Z',
            revoked: false,
            spec_version: '2.1',
            type: 'report' }],
        more: undefined
      },
      addedLastHeader: undefined
    };

    await processTaxiiResponse(testContext, ingestion, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestion.id);
    expect(result.current_state_cursor).toBe('1234');
    expect(result.taxii_more).toBeUndefined();
    expect(result.added_after_start).toBeUndefined();
  });

  it('should taxii server response with data and only added_last', async () => {
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
            type: 'report' }],
        more: undefined
      },
      addedLastHeader: '2021-11-11T11:11:11.111Z'
    };

    await processTaxiiResponse(testContext, ingestion, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestion.id);
    expect(result.current_state_cursor).toBeUndefined();
    expect(result.taxii_more).toBeUndefined();
    expect(result.added_after_start).toBe('2021-11-11T11:11:11.111Z');
  });

  it('should taxii server response without data ignore next and added_last', async () => {
    // First put values
    const taxiResponseWithData: TaxiiResponseData = {
      data: {
        next: '444444',
        objects: [
          { confidence: 100,
            created: '2024-06-03T20:35:44.000Z',
            description: 'The best description of the world',
            published: '2024-06-03T20:35:44.000Z',
            revoked: false,
            spec_version: '2.1',
            type: 'report' }],
        more: false
      },
      addedLastHeader: '2022-12-22T22:22:22.222Z'
    };

    await processTaxiiResponse(testContext, ingestion, taxiResponseWithData);
    const resultWithData = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestion.id);
    expect(resultWithData.current_state_cursor).toBe('444444');
    expect(resultWithData.taxii_more).toBeFalsy();
    expect(resultWithData.added_after_start).toBe('2022-12-22T22:22:22.222Z');

    const taxiResponse: TaxiiResponseData = {
      data: {
        next: '55555',
        objects: [],
        more: false
      },
      addedLastHeader: '2021-11-11T11:11:11.111Z'
    };

    await processTaxiiResponse(testContext, ingestion, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestion.id);
    expect(result.current_state_cursor).toBe('444444'); // should not be updated when no data
    expect(result.taxii_more).toBeFalsy();
    expect(result.added_after_start).toBe('2022-12-22T22:22:22.222Z');
  });

  it('should do nothing when no data but more is true', async () => {
    const taxiResponse: TaxiiResponseData = {
      data: {
        next: undefined,
        objects: [],
        more: true
      },
      addedLastHeader: '2021-11-11T11:11:11.111Z'
    };

    await processTaxiiResponse(testContext, ingestion, taxiResponse);
    const result = await findTaxiiIngestionById(testContext, ADMIN_USER, ingestion.id);
    expect(result.current_state_cursor).toBe('444444'); // previous values
    expect(result.taxii_more).toBeFalsy();
    expect(result.added_after_start).toBe('2022-12-22T22:22:22.222Z');
  });
});
