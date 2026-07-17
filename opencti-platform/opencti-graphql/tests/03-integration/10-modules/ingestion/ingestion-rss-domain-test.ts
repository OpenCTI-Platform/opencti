import { afterAll, describe, expect, it, vi } from 'vitest';
import { addIngestion, ingestionDelete, ingestionEditField } from '../../../../src/modules/ingestion/ingestion-rss-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type EditInput, type IngestionRssAddInput } from '../../../../src/generated/graphql';
import * as uriDenyListConfigMock from '../../../../src/config/uriDenyList';
import type { BasicStoreEntityIngestionRss } from '../../../../src/modules/ingestion/ingestion-types';

describe('Ingestion Rss domain - Deny list coverage', async () => {
  let myRssFeed: BasicStoreEntityIngestionRss;

  afterAll(async () => {
    if (myRssFeed && myRssFeed.id) {
      await ingestionDelete(testContext, ADMIN_USER, myRssFeed.id);
    }
  });

  it('should be able to create a RSS feed with an allowed URI, and refused field patch of denied URL', async () => {
    vi.spyOn(uriDenyListConfigMock, 'uriDenyList').mockReturnValue(['*.denied.com']);

    const creationInput: IngestionRssAddInput = {
      name: 'Test RSS feed deny list',
      uri: 'https://example.allowed.com/rss-feed',
      user_id: ADMIN_USER.id,
    };
    myRssFeed = await addIngestion(testContext, ADMIN_USER, creationInput) as unknown as BasicStoreEntityIngestionRss;

    const fieldPatchInput: EditInput[] = [{
      key: 'uri',
      value: ['https://example.denied.com/rss-feed'],
    }];
    await expect(ingestionEditField(testContext, ADMIN_USER, myRssFeed.id, fieldPatchInput))
      .rejects.toThrow('This URI is not allowed for ingestion.');
  });
});
