import { afterAll, describe, expect, it, vi } from 'vitest';
import { ingestionTaxiiAdd, ingestionTaxiiDelete, ingestionTaxiiEditField } from '../../../../src/modules/ingestion/ingestion-taxii-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type EditInput, IngestionAuthType, type IngestionTaxiiAddInput, TaxiiVersion } from '../../../../src/generated/graphql';
import * as uriDenyListConfigMock from '../../../../src/config/uriDenyList';
import type { BasicStoreEntityIngestionTaxii } from '../../../../src/modules/ingestion/ingestion-types';

describe('Ingestion Taxii domain - Deny list coverage', async () => {
  let myTaxiiFeed: BasicStoreEntityIngestionTaxii;

  afterAll(async () => {
    if (myTaxiiFeed && myTaxiiFeed.id) {
      await ingestionTaxiiDelete(testContext, ADMIN_USER, myTaxiiFeed.id);
    }
  });

  it('should be able to create a taxii feed with an allowed URI, and refused field patch of denied URL', async () => {
    vi.spyOn(uriDenyListConfigMock, 'uriDenyList').mockReturnValue(['*.denied.com']);

    const creationInput: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testing',
      user_id: ADMIN_USER.id,
      version: TaxiiVersion.V21,
      name: 'Test TAXII feed',
      uri: 'https://example.allowed.com/taxii-feed',
    };
    myTaxiiFeed = await ingestionTaxiiAdd(testContext, ADMIN_USER, creationInput);

    const fieldPatchInput: EditInput[] = [{
      key: 'uri',
      value: ['https://example.denied.com/taxii-feed'],
    }];
    await expect(ingestionTaxiiEditField(testContext, ADMIN_USER, myTaxiiFeed.id, fieldPatchInput))
      .rejects.toThrow('This URI is not allowed for ingestion.');
  });
});
