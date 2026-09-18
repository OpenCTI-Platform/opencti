import { describe, it, expect } from 'vitest';
import { getEntitiesMapFromCache, writeCacheForEntity } from '../../../src/database/cache';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { AuthContext } from '../../../src/types/user';

const testContext = {} as AuthContext;
const ENTITY_TYPE_TEST_USER = 'TestUser';

describe('Cache entities map building', () => {
  it('should only index entities by internal_id/standard_id/stix ids, ignoring any other entity attribute', async () => {
    const entityA = {
      internal_id: 'entity-a-internal-id',
      standard_id: 'user--entity-a-standard-id',
      entity_type: ENTITY_TYPE_TEST_USER,
    };
    // entityB carries a secondary attribute whose value happens to collide with entityA's internal_id.
    // This must never be used as a lookup key for the map.
    const entityB = {
      internal_id: 'entity-b-internal-id',
      standard_id: 'user--entity-b-standard-id',
      entity_type: ENTITY_TYPE_TEST_USER,
      api_tokens: [{ id: 'token-id', hash: 'entity-a-internal-id' }],
    };
    writeCacheForEntity(ENTITY_TYPE_TEST_USER, { values: [entityA, entityB], fn: async () => [entityA, entityB] });

    const map = await getEntitiesMapFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_USER);

    // Resolving by entityA's internal_id must still return entityA, not entityB.
    expect(map.get('entity-a-internal-id')).toEqual(entityA);
    expect(map.get('entity-a-internal-id')).not.toEqual(entityB);
    // No extra entry should exist for the secondary attribute's own id/value.
    expect(map.get('token-id')).toBeUndefined();
  });

  it('should still index entities by internal_id, standard_id and stix ids', async () => {
    const entity = {
      internal_id: 'entity-internal-id',
      standard_id: 'user--entity-standard-id',
      entity_type: ENTITY_TYPE_TEST_USER,
      x_opencti_stix_ids: ['user--legacy-stix-id'],
    };
    writeCacheForEntity(ENTITY_TYPE_TEST_USER, { values: [entity], fn: async () => [entity] });

    const map = await getEntitiesMapFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_USER);

    expect(map.get('entity-internal-id')).toEqual(entity);
    expect(map.get('user--entity-standard-id')).toEqual(entity);
    expect(map.get('user--legacy-stix-id')).toEqual(entity);
  });
});
