import { describe, it, expect } from 'vitest';
import {
  addCacheForEntity,
  getEntitiesListFromCache,
  getEntitiesMapFromCache,
  MAX_CACHE_DISCARDS,
  refreshCacheForEntity,
  removeCacheForEntity,
  resetCacheForEntity,
  writeCacheForEntity,
} from '../../../src/database/cache';
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

const ENTITY_TYPE_TEST_RACE = 'TestCacheRace';

// A cache loader whose every call is resolved by the test, in order, so a change can land while a load is in flight.
const createControlledLoader = () => {
  const pending: Array<(value: unknown[]) => void> = [];
  const fn = () => new Promise<unknown[]>((resolve) => {
    pending.push(resolve);
  });
  // Yields to the event loop until the cache started a load (never resolves a load before it exists).
  // Bounded, so a load that never starts fails the test at once instead of at the vitest timeout.
  const waitForLoad = async () => {
    let ticks = 0;
    while (pending.length === 0) {
      ticks += 1;
      if (ticks > 50) {
        throw new Error('The cache did not start the expected load');
      }
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
    expect(loader.pendingCount()).toBe(0);
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
    expect(loader.pendingCount()).toBe(0);
  });

  it('should serve the waiting readers without storing the values once every load was overtaken up to the cap', async () => {
    const loader = createControlledLoader();
    writeCacheForEntity(ENTITY_TYPE_TEST_RACE, { values: undefined, fn: loader.fn });

    const read = getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE);
    for (let load = 1; load <= MAX_CACHE_DISCARDS; load += 1) {
      await loader.waitForLoad();
      resetCacheForEntity(ENTITY_TYPE_TEST_RACE);
      await loader.resolveNext([{ ...before, load }]);
    }

    // The reader gets the last loaded values instead of waiting for the invalidations to stop
    expect(await read).toEqual([{ ...before, load: MAX_CACHE_DISCARDS }]);
    expect(loader.pendingCount()).toBe(0);
    // Those values were not stored: the next read loads again
    const next = getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE);
    await loader.resolveNext([after]);
    expect(await next).toEqual([after]);
    expect(loader.pendingCount()).toBe(0);
  });

  it('should leave the entry cleared when a reset lands while an incremental refresh is in flight', async () => {
    const handler = createControlledLoader();
    const loader = createControlledLoader();
    writeCacheForEntity(ENTITY_TYPE_TEST_RACE, {
      values: [before],
      fn: loader.fn,
      // Computes the refreshed values from the values read before its await, like refreshUsers or refreshFilter
      refresh: async (values: unknown[]) => [...values, ...(await handler.fn())],
    });

    const refresh = refreshCacheForEntity(after as never);
    await handler.waitForLoad();
    // The reset lands while the refresh still holds the values read before it
    resetCacheForEntity(ENTITY_TYPE_TEST_RACE);
    await handler.resolveNext([after]);
    await refresh;

    // The refresh did not write back over the reset: the next read loads again
    const read = getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE);
    await loader.resolveNext([after]);
    expect(await read).toEqual([after]);
    expect(loader.pendingCount()).toBe(0);
  });

  it('should apply two concurrent incremental refreshes of the same entry', async () => {
    const handler = createControlledLoader();
    const first = { internal_id: 'race-first', entity_type: ENTITY_TYPE_TEST_RACE };
    const second = { internal_id: 'race-second', entity_type: ENTITY_TYPE_TEST_RACE };
    writeCacheForEntity(ENTITY_TYPE_TEST_RACE, {
      values: [before],
      fn: async () => [before],
      refresh: async (values: unknown[], instance: { internal_id: string }) => {
        const reloaded = await handler.fn();
        return [...values.filter((v) => (v as { internal_id: string }).internal_id !== instance.internal_id), ...reloaded];
      },
    });

    const firstRefresh = refreshCacheForEntity(first as never);
    const secondRefresh = refreshCacheForEntity(second as never);
    await handler.resolveNext([first]);
    await handler.resolveNext([second]);
    await Promise.all([firstRefresh, secondRefresh]);

    expect(handler.pendingCount()).toBe(0);
    expect(await getEntitiesListFromCache(testContext, SYSTEM_USER, ENTITY_TYPE_TEST_RACE)).toEqual([before, first, second]);
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
