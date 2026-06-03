import { afterAll, describe, expect, it, vi } from 'vitest';
import { addTaxiiIngestion, ingestionDelete, ingestionEditField } from '../../../../src/modules/ingestion/ingestion-taxii-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type EditInput, IngestionAuthType, type IngestionTaxiiAddInput, TaxiiVersion } from '../../../../src/generated/graphql';
import * as ingestionConfigMock from '../../../../src/manager/ingestionManager/ingestionManagerConfiguration';
import type { BasicStoreEntityIngestionTaxii } from '../../../../src/modules/ingestion/ingestion-types';

describe('Ingestion Taxii domain - Deny list coverage', async () => {
  let myTaxiiFeed: BasicStoreEntityIngestionTaxii;

  afterAll(async () => {
    if (myTaxiiFeed && myTaxiiFeed.id) {
      await ingestionDelete(testContext, ADMIN_USER, myTaxiiFeed.id);
    }
  });

  it('should be able to create a taxii feed with an allowed URI, and refused field patch of denied URL', async () => {
    vi.spyOn(ingestionConfigMock, 'ingestionUriDenyList').mockReturnValue(['*.denied.com']);

    const creationInput: IngestionTaxiiAddInput = {
      authentication_type: IngestionAuthType.None,
      collection: 'testing',
      user_id: ADMIN_USER.id,
      version: TaxiiVersion.V21,
      name: 'Test TAXII feed',
      uri: 'https://example.allowed.com/taxii-feed',
    };
    myTaxiiFeed = await addTaxiiIngestion(testContext, ADMIN_USER, creationInput);

    const fieldPatchInput: EditInput[] = [{
      key: 'uri',
      value: ['https://example.denied.com/taxii-feed'],
    }];
    await expect(ingestionEditField(testContext, ADMIN_USER, myTaxiiFeed.id, fieldPatchInput))
      .rejects.toThrow('This URI is not allowed for ingestion.');
  });
});
