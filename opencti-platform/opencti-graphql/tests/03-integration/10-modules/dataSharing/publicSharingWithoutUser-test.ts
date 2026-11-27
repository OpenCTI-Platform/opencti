import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import conf, { BUS_TOPICS, getBaseUrl } from '../../../../src/config/conf';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { patchAttribute } from '../../../../src/database/middleware';
import { notify } from '../../../../src/database/redis';
import { createFeed, feedDelete, findById as findFeedById } from '../../../../src/modules/dataSharing/feed-domain';
import { createTaxiiCollection, taxiiCollectionDelete } from '../../../../src/modules/dataSharing/taxiiCollection-domain';
import { createStreamCollection, streamCollectionDelete } from '../../../../src/modules/dataSharing/streamCollection-domain';
import { findPublicSharingsWithoutUser, resetPublicSharingWarnings } from '../../../../src/modules/dataSharing/dataSharing-utils';
import { ENTITY_TYPE_FEED } from '../../../../src/modules/dataSharing/feed-types';
import { ENTITY_TYPE_TAXII_COLLECTION } from '../../../../src/modules/dataSharing/taxiiCollection-types';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../../../../src/modules/dataSharing/streamCollection-types';
import { resolveUserForFeed } from '../../../../src/http/httpRollingFeed';
// eslint-disable-next-line import/extensions
import { extractUserAndCollection } from '../../../../src/http/httpTaxii.js';
// eslint-disable-next-line import/extensions
import { authenticateForPublic } from '../../../../src/graphql/sseMiddleware.js';

// Public collections created before the public user setting have none.
// The HTTP server of the tests runs in another process: the switch set here only applies to the calls made in this process.
const SECURE_KEY = 'app:data_sharing:secure_by_default';
const DOMAIN_NAME_FILTERS = JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', values: ['Domain-Name'], mode: 'or' }], filterGroups: [] });

// Clears the public user as an old platform stored it: the collection stays public
const clearPublicUser = async (id: string, entityType: string, userIdField: string) => {
  const { element } = await patchAttribute(testContext, SYSTEM_USER, id, entityType, { [userIdField]: null }, { operations: { [userIdField]: 'remove' } });
  const busTopic = (BUS_TOPICS as Record<string, { EDIT_TOPIC?: string } | undefined>)[entityType];
  if (busTopic?.EDIT_TOPIC) {
    await notify(busTopic.EDIT_TOPIC, element, SYSTEM_USER);
  }
};

const makeStreamRequest = (id: string) => ({ params: { id }, headers: {}, query: {}, on: vi.fn() }) as any;
const makeStreamResponse = () => ({ statusMessage: '', status: vi.fn().mockReturnThis(), end: vi.fn().mockReturnThis(), on: vi.fn() }) as any;

describe('Public sharing without a public user', () => {
  let feedId: string;
  let taxiiId: string;
  let streamId: string;

  beforeAll(async () => {
    const feed = await createFeed(testContext, ADMIN_USER, {
      name: 'Legacy public feed without public user',
      separator: ',',
      rolling_time: 60,
      include_header: true,
      feed_types: ['Domain-Name'],
      feed_date_attribute: 'created_at',
      feed_attributes: [{ attribute: 'value', mappings: [{ type: 'Domain-Name', attribute: 'value' }] }],
      feed_public: true,
      feed_public_user_id: ADMIN_USER.id,
    });
    feedId = feed.id;
    const taxii = await createTaxiiCollection(testContext, ADMIN_USER, {
      name: 'Legacy public taxii collection without public user',
      filters: DOMAIN_NAME_FILTERS,
      taxii_public: true,
      taxii_public_user_id: ADMIN_USER.id,
    });
    taxiiId = taxii.id;
    const stream = await createStreamCollection(testContext, ADMIN_USER, {
      name: 'Legacy public stream without public user',
      filters: DOMAIN_NAME_FILTERS,
      stream_public: true,
      stream_public_user_id: ADMIN_USER.id,
      stream_live: true,
    });
    streamId = stream.id;
    await clearPublicUser(feedId, ENTITY_TYPE_FEED, 'feed_public_user_id');
    await clearPublicUser(taxiiId, ENTITY_TYPE_TAXII_COLLECTION, 'taxii_public_user_id');
    await clearPublicUser(streamId, ENTITY_TYPE_STREAM_COLLECTION, 'stream_public_user_id');
  });

  afterEach(() => {
    conf.clear(SECURE_KEY);
    resetPublicSharingWarnings();
  });

  afterAll(async () => {
    await feedDelete(testContext, ADMIN_USER, feedId);
    await taxiiCollectionDelete(testContext, ADMIN_USER, taxiiId);
    await streamCollectionDelete(testContext, ADMIN_USER, streamId);
  });

  it('should list the three collections for the startup warning', async () => {
    const collections = await findPublicSharingsWithoutUser(testContext);
    expect(collections).toEqual(expect.arrayContaining([
      { entity_type: ENTITY_TYPE_FEED, id: feedId, name: 'Legacy public feed without public user' },
      { entity_type: ENTITY_TYPE_TAXII_COLLECTION, id: taxiiId, name: 'Legacy public taxii collection without public user' },
      { entity_type: ENTITY_TYPE_STREAM_COLLECTION, id: streamId, name: 'Legacy public stream without public user' },
    ]));
  });

  describe('app:data_sharing:secure_by_default=false', () => {
    it('should serve the CSV feed as SYSTEM_USER', async () => {
      const feed = await findFeedById(testContext, SYSTEM_USER, feedId);
      expect(await resolveUserForFeed(testContext, feed)).toBe(SYSTEM_USER);
      const response = await fetch(`${getBaseUrl()}/feeds/${feedId}`);
      expect(response.status).toBe(200);
    });

    it('should serve the TAXII collection as SYSTEM_USER', async () => {
      const { user } = await extractUserAndCollection(makeStreamRequest(taxiiId), makeStreamResponse(), taxiiId);
      expect(user).toBe(SYSTEM_USER);
      const response = await fetch(`${getBaseUrl()}/taxii2/root/collections/${taxiiId}/objects/`, { headers: { Accept: 'application/taxii+json;version=2.1' } });
      await response.body?.cancel();
      expect(response.status).toBe(200);
    });

    it('should serve the live stream as SYSTEM_USER', async () => {
      const req = makeStreamRequest(streamId);
      const next = vi.fn();
      await authenticateForPublic(req, makeStreamResponse(), next);
      expect(next).toHaveBeenCalled();
      expect(req.user).toBe(SYSTEM_USER);
      const response = await fetch(`${getBaseUrl()}/stream/${streamId}`, { headers: { Accept: 'text/event-stream' } });
      await response.body?.cancel();
      expect(response.status).toBe(200);
    });
  });

  describe('app:data_sharing:secure_by_default=true', () => {
    it('should refuse the CSV feed', async () => {
      conf.set(SECURE_KEY, true);
      const feed = await findFeedById(testContext, SYSTEM_USER, feedId);
      await expect(resolveUserForFeed(testContext, feed)).rejects.toMatchObject({
        message: `The public csv feed ${feedId} has no public user: an administrator must configure one to serve it`,
        extensions: { code: 'FORBIDDEN_ACCESS', data: { http_status: 403 } },
      });
    });

    it('should refuse the TAXII collection', async () => {
      conf.set(SECURE_KEY, true);
      await expect(extractUserAndCollection(makeStreamRequest(taxiiId), makeStreamResponse(), taxiiId)).rejects.toMatchObject({
        message: `The public Taxii collection ${taxiiId} has no public user: an administrator must configure one to serve it`,
        extensions: { code: 'FORBIDDEN_ACCESS', data: { http_status: 403 } },
      });
    });

    it('should refuse the live stream with a 403', async () => {
      conf.set(SECURE_KEY, true);
      const req = makeStreamRequest(streamId);
      const res = makeStreamResponse();
      const next = vi.fn();
      await authenticateForPublic(req, res, next);
      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.statusMessage).toBe(`The public live stream ${streamId} has no public user: an administrator must configure one to serve it`);
    });
  });
});
