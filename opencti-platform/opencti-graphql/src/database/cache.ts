import type { BasicStoreEntity } from '../types/store';
import { UnsupportedError } from '../config/errors';

const cache: any = {};

export const writeCacheForEntity = (entityType: string, data: unknown) => {
  cache[entityType] = data;
};

export const resetCacheForEntity = (entityType: string) => {
  if (cache[entityType]) {
    cache[entityType].values = undefined;
  } else {
    // This entity type is not part of the caching system
  }
};

export const getEntitiesFromCache = async<T extends BasicStoreEntity>(type: string): Promise<Array<T>> => {
  const fromCache = cache[type];
  if (!fromCache) {
    throw UnsupportedError(`${type} is not supported in cache configuration`);
  }
  if (!fromCache.values) {
    fromCache.values = await fromCache.fn();
  }
  return fromCache.values ?? [];
};

export const getEntityFromCache = async<T extends BasicStoreEntity>(type: string): Promise<T> => {
  const data = await getEntitiesFromCache<T>(type);
  return data[0];
};
