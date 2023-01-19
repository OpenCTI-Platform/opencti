import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import type { BasicStoreEntity } from '../types/store';
import { UnsupportedError } from '../config/errors';
import { telemetry } from '../config/tracing';
import type { AuthContext, AuthUser } from '../types/user';

const cache: any = {};

const buildStoreEntityMap = <T extends BasicStoreEntity>(entities: Array<T>) => {
  const entityById = new Map();
  for (let i = 0; i < entities.length; i += 1) {
    const entity = entities[i];
    const ids = [entity.internal_id, entity.standard_id, ...(entity.x_opencti_stix_ids ?? [])];
    for (let index = 0; index < ids.length; index += 1) {
      const id = ids[index];
      entityById.set(id, entity);
    }
  }
  return entityById;
};

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

export const getEntitiesFromCache = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, type: string)
: Promise<Array<T>> => {
  const getEntitiesFromCacheFn = async (): Promise<Array<T> | Map<string, T>> => {
    const fromCache = cache[type];
    if (!fromCache) {
      throw UnsupportedError(`${type} is not supported in cache configuration`);
    }
    if (!fromCache.values) {
      fromCache.values = await fromCache.fn();
    }
    return fromCache.values ?? [];
  };
  return telemetry(context, user, `CACHE ${type}`, {
    [SemanticAttributes.DB_NAME]: 'cache_engine',
    [SemanticAttributes.DB_OPERATION]: 'select',
  }, getEntitiesFromCacheFn);
};

export const getEntitiesMapFromCache = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, type: string): Promise<Map<string, T>> => {
  const data = await getEntitiesFromCache(context, user, type);
  return buildStoreEntityMap(data);
};

export const getEntityFromCache = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, type: string): Promise<T> => {
  const data = await getEntitiesFromCache<T>(context, user, type);
  return data[0];
};
