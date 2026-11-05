import { describe, it, expect } from 'vitest';
import { getEntitiesListFromCache, getEntitiesMapFromCache, refreshCacheForEntity, resetCacheForEntity, writeCacheForEntity } from '../../../src/database/cache';
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

const ENTITY_TYPE_TEST_RACE = 'TestCacheRace';

// A cache loader whose every call is resolved by the test, in order, so a change can land while a load is in flight.
const createControlledLoader = () => {
  const pending: Array<(value: unknown[]) => void> = [];
  const fn = () => new Promise<unknown[]>((resolve) => {
    pending.push(resolve);
  });
  // Yields to the event loop until the cache started a load (never resolves a load before it exists)
  const waitForLoad = async () => {
    while (pending.length === 0) {
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  };
  const resolveNext = async (value: unknown[]) => {
    await waitForLoad();
    pending.shift()!(value);
  };
  return { fn, resolveNext, waitForLoad, pendingCount: () => pending.length };
};

describe('Cache invalidation while a load is in flight', () => {
  const before = { internal_id: 'race-entity', entity_type: ENTITY_TYPE_TEST_RACE, running: false };
  const after = { ...before, running: true };

  it('should not keep the values of a load overtaken by an edit of the cached type', async () => {
    const loader = createControlledLoader();
    writeCacheForEntity(ENTITY_TYPE_TEST_RACE, { values: undefined, fn: loader.fn });

    const read = getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE);
    // The edit lands while the first load still holds the data read before it
    await loader.waitForLoad();
    await refreshCacheForEntity(after as never);
    await loader.resolveNext([before]);
    // The overtaken load is discarded and the cache loads again
    await loader.resolveNext([after]);

    expect(await read).toEqual([after]);
    expect(await getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE)).toEqual([after]);
  });

  it('should not keep the values of a load overtaken by a reset of the cached type', async () => {
    const loader = createControlledLoader();
    writeCacheForEntity(ENTITY_TYPE_TEST_RACE, { values: undefined, fn: loader.fn });

    const read = getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE);
    await loader.waitForLoad();
    resetCacheForEntity(ENTITY_TYPE_TEST_RACE);
    await loader.resolveNext([before]);
    await loader.resolveNext([after]);

    expect(await read).toEqual([after]);
  });

  it('should keep the values of a load that no change overtook', async () => {
    const loader = createControlledLoader();
    writeCacheForEntity(ENTITY_TYPE_TEST_RACE, { values: undefined, fn: loader.fn });

    const read = getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE);
    await loader.resolveNext([before]);

    expect(await read).toEqual([before]);
    expect(loader.pendingCount()).toBe(0);
  });
});
