import { afterAll, describe, expect, it, vi } from 'vitest';
import { addIngestionJson, deleteIngestionJson, ingestionJsonEditField, testJsonIngestionMapping } from '../../../../src/modules/ingestion/ingestion-json-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type EditInput, IngestionAuthType, type IngestionJsonAddInput } from '../../../../src/generated/graphql';
import * as ingestionConfigMock from '../../../../src/manager/ingestionManager/ingestionManagerConfiguration';
import type { BasicStoreEntityIngestionJson } from '../../../../src/modules/ingestion/ingestion-types';

describe('Ingestion Json domain - Deny list coverage', async () => {
  let myJsonFeed: BasicStoreEntityIngestionJson;

  afterAll(async () => {
    if (myJsonFeed && myJsonFeed.id) {
      await deleteIngestionJson(testContext, ADMIN_USER, myJsonFeed.id);
    }
  });

  it('should be able to create a JSON feed with an allowed URI, and refused field patch of denied URL', async () => {
    vi.spyOn(ingestionConfigMock, 'ingestionUriDenyList').mockReturnValue(['*.denied.com']);

    const creationInput: IngestionJsonAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Test JSON feed deny list',
      uri: 'https://example.allowed.com/json-feed',
      user_id: ADMIN_USER.id,
      json_mapper_id: 'fake-mapper-id',
      verb: 'GET',
    };
    myJsonFeed = await addIngestionJson(testContext, ADMIN_USER, creationInput) as unknown as BasicStoreEntityIngestionJson;

    const fieldPatchInput: EditInput[] = [{
      key: 'uri',
      value: ['https://example.denied.com/json-feed'],
    }];
    await expect(ingestionJsonEditField(testContext, ADMIN_USER, myJsonFeed.id, fieldPatchInput))
      .rejects.toThrow('This URI is not allowed for ingestion.');
  });

  it('should test be denied when URL is in deny list', async () => {
    vi.spyOn(ingestionConfigMock, 'ingestionUriDenyList').mockReturnValue(['*.denied.com']);

    const testInput: IngestionJsonAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Test JSON feed deny list',
      uri: 'https://example.denied.com/json-feed',
      user_id: ADMIN_USER.id,
      json_mapper_id: 'fake-mapper-id',
      verb: 'GET',
    };
    await expect(testJsonIngestionMapping(testContext, ADMIN_USER, testInput))
      .rejects.toThrow('This URI is not allowed for ingestion.');
  });
});
