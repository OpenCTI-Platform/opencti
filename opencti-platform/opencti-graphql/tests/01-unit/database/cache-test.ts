import { describe, it, expect } from 'vitest';
import { addCacheForEntity, getEntitiesMapFromCache, refreshCacheForEntity, removeCacheForEntity, resetCacheForEntity, writeCacheForEntity } from '../../../src/database/cache';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { AuthContext } from '../../../src/types/user';
import type { BasicStoreCommon } from '../../../src/types/store';

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

describe('Cache entities map reuse', () => {
  const buildEntity = (name: string, entityType: string) => ({
    internal_id: `${name}-internal-id`,
    standard_id: `user--${name}-standard-id`,
    entity_type: entityType,
  });

  it('should build the map once and return the same map while the values do not change', async () => {
    const type = 'TestReuseUser';
    const entity = buildEntity('entity', type);
    writeCacheForEntity(type, { values: [entity], fn: async () => [entity] });

    const firstMap = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    const secondMap = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);

    expect(secondMap).toBe(firstMap);
    expect(secondMap.get('entity-internal-id')).toEqual(entity);
  });

  it('should build the map again when the values are updated in place', async () => {
    const type = 'TestInPlaceUser';
    const entityA = buildEntity('entity-a', type);
    const entityB = buildEntity('entity-b', type);
    // Like the users cache, the add function pushes into the existing values and returns the same array
    const add = async (values: unknown[], instance: unknown) => {
      values.push(instance);
      return values;
    };
    writeCacheForEntity(type, { values: [entityA], fn: async () => [entityA], add });
    const mapBefore = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    expect(mapBefore.get('entity-b-internal-id')).toBeUndefined();

    await addCacheForEntity(entityB as unknown as BasicStoreCommon);

    const mapAfter = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    expect(mapAfter).not.toBe(mapBefore);
    expect(mapAfter.get('entity-a-internal-id')).toEqual(entityA);
    expect(mapAfter.get('entity-b-internal-id')).toEqual(entityB);
  });

  it('should build the map again when the values are refreshed, removed or reset', async () => {
    const type = 'TestRefreshUser';
    const entity = buildEntity('entity', type);
    const renamedEntity = { ...entity, name: 'renamed' };
    let loadedValues: unknown[] = [entity];
    writeCacheForEntity(type, {
      values: [entity],
      fn: async () => loadedValues,
      refresh: async () => [renamedEntity],
      remove: async () => [],
    });
    const initialMap = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);

    await refreshCacheForEntity(renamedEntity as unknown as BasicStoreCommon);
    const refreshedMap = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    expect(refreshedMap).not.toBe(initialMap);
    expect(refreshedMap.get('entity-internal-id')).toEqual(renamedEntity);

    await removeCacheForEntity(renamedEntity as unknown as BasicStoreCommon);
    const removedMap = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    expect(removedMap.get('entity-internal-id')).toBeUndefined();

    const reloadedEntity = { ...entity, name: 'reloaded' };
    loadedValues = [reloadedEntity];
    resetCacheForEntity(type);
    const reloadedMap = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    expect(reloadedMap.get('entity-internal-id')).toEqual(reloadedEntity);
  });

  it('should not keep a map built from values replaced while they were fetched', async () => {
    const type = 'TestReplacedUser';
    const oldEntity = buildEntity('old', type);
    const newEntity = buildEntity('new', type);
    writeCacheForEntity(type, { values: [oldEntity], fn: async () => [oldEntity] });

    // The values are read when the call starts, then the cache entry is replaced before the call ends
    const pendingMap = getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    const newCacheEntry: Record<string, unknown> = { values: [newEntity], fn: async () => [newEntity] };
    writeCacheForEntity(type, newCacheEntry);

    const oldMap = await pendingMap;
    expect(oldMap.get('old-internal-id')).toEqual(oldEntity);
    expect(newCacheEntry.entitiesMap).toBeUndefined();
    const newMap = await getEntitiesMapFromCache(testContext, SYSTEM_USER, type);
    expect(newMap.get('new-internal-id')).toEqual(newEntity);
    expect(newMap.get('old-internal-id')).toBeUndefined();
  });
});
