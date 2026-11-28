import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR } from '../../utils/testQuery';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreRelation, StoreObject } from '../../../src/types/store';
import { resolveUserByIdFromCache } from '../../../src/modules/user/user-domain';
import { addSector } from '../../../src/domain/sector';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import { deleteElementById, storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { fullRelationsList } from '../../../src/database/middleware-loader';
import { elRawSearch } from '../../../src/database/engine';
import { READ_DATA_INDICES_WITHOUT_INFERRED } from '../../../src/database/utils';
import { RELATION_CREATED_BY } from '../../../src/schema/stixRefRelationship';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { MARKING_TLP_AMBER } from '../../../src/schema/identifier';

const loadRawSource = async (internalId: string) => {
  const result = await elRawSearch(testContext, ADMIN_USER, null, {
    index: READ_DATA_INDICES_WITHOUT_INFERRED,
    body: { query: { bool: { filter: [{ term: { 'internal_id.keyword': internalId } }] } } },
  });
  return result.hits.hits[0]._source;
};

// Issue #17885: a connector upserts an entity whose author it cannot see.
// The test connector user only sees TLP:GREEN, so an author marked TLP:AMBER is invisible to it.
describe('Upsert of an entity whose created-by is invisible to the writer', () => {
  let connectorUser: AuthUser;
  let hiddenAuthorId: string;
  let visibleAuthorId: string;
  let sectorId: string;

  beforeAll(async () => {
    connectorUser = await resolveUserByIdFromCache(testContext, await getUserIdByEmail(USER_CONNECTOR.email)) as AuthUser;
    const hiddenAuthor = await addOrganization(testContext, ADMIN_USER, {
      name: 'issue-17885 hidden author',
      objectMarking: [MARKING_TLP_AMBER],
    });
    hiddenAuthorId = hiddenAuthor.id;
    const visibleAuthor = await addOrganization(testContext, ADMIN_USER, { name: 'issue-17885 connector author' });
    visibleAuthorId = visibleAuthor.id;
    const sector = await addSector(testContext, ADMIN_USER, { name: 'issue-17885 sector', createdBy: hiddenAuthorId, confidence: 100 });
    sectorId = sector.id;
  });

  afterAll(async () => {
    await deleteElementById(testContext, ADMIN_USER, sectorId, ENTITY_TYPE_IDENTITY_SECTOR);
    await deleteElementById(testContext, ADMIN_USER, visibleAuthorId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    await deleteElementById(testContext, ADMIN_USER, hiddenAuthorId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  });

  it('should not see the hidden author as the connector', async () => {
    const sectorAsConnector = await storeLoadByIdWithRefs(testContext, connectorUser, sectorId);
    expect(sectorAsConnector).toBeDefined();
    expect((sectorAsConnector as StoreObject).createdBy).toBeUndefined();
  });

  it('should keep a single created-by relation after the connector upsert', async () => {
    // Same name, so same standard id: this is an upsert, not a creation.
    await addSector(testContext, connectorUser, { name: 'issue-17885 sector', createdBy: visibleAuthorId });

    const createdByRelations = await fullRelationsList<BasicStoreRelation>(testContext, ADMIN_USER, RELATION_CREATED_BY, { fromId: sectorId });
    expect(createdByRelations).toHaveLength(1);
    const [authorId] = createdByRelations.map((r) => r.toId);

    // The denormalized field read by lists and the relations read by the STIX export name the same author
    const rawSector = await loadRawSource(sectorId);
    expect(rawSector[`rel_${RELATION_CREATED_BY}.internal_id`]).toEqual([authorId]);
    const sectorAsAdmin = await storeLoadByIdWithRefs(testContext, ADMIN_USER, sectorId);
    expect((sectorAsAdmin as StoreObject).createdBy?.internal_id).toEqual(authorId);
  });

  // The connector confidence (100) is not strictly above the entity's (100), so the author must not be replaced,
  // whatever the answer to the product question on #17885. Needs the upsert to stop treating an invisible ref as empty.
  it.todo('should keep the hidden author when the connector confidence is not strictly higher');
});
