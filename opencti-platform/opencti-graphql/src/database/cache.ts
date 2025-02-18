import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import type { BasicStoreCommon, BasicStoreIdentifier } from '../types/store';
import { logApp } from '../config/conf';
import { UnsupportedError } from '../config/errors';
import { telemetry } from '../config/tracing';
import type { AuthContext, AuthUser } from '../types/user';
import type { StixId, StixObject } from '../types/stix-common';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../schema/stixDomainObject';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { type BasicStoreEntityPublicDashboard, ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { wait } from './utils';

const STORE_ENTITIES_LINKS: Record<string, string[]> = {
  // Filters must be reset depending on stream and triggers modifications
  [ENTITY_TYPE_STREAM_COLLECTION]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_TRIGGER]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_PLAYBOOK]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_CONNECTOR]: [ENTITY_TYPE_RESOLVED_FILTERS],
};

const cache: any = {};

const buildStoreEntityMap = <T extends BasicStoreIdentifier>(entities: Array<T>) => {
  const entityById = new Map();
  for (let i = 0; i < entities.length; i += 1) {
    const entity = entities[i];
    const ids = [entity.internal_id, ...(entity.x_opencti_stix_ids ?? [])];
    // Use the user api_token as an id
    if ('api_token' in entity && entity.api_token) {
      ids.push(entity.api_token as string);
    }
    if (entity.standard_id) {
      ids.push(entity.standard_id);
    }
    for (let index = 0; index < ids.length; index += 1) {
      const id = ids[index];
      entityById.set(id, entity);
    }
  }
  return entityById;
};

const buildStorePublicDashboardMap = <T extends BasicStoreEntityPublicDashboard>(entities: Array<T>) => {
  const entityByUriKey = new Map();
  for (let i = 0; i < entities.length; i += 1) {
    const entity = entities[i];
    const { uri_key } = entity;
    entityByUriKey.set(uri_key, entity);
  }
  return entityByUriKey;
};

export const writeCacheForEntity = (entityType: string, data: unknown) => {
  cache[entityType] = data;
};

export const resetCacheForEntity = (entityType: string) => {
  const types = [entityType, ...(STORE_ENTITIES_LINKS[entityType] ?? [])];
  types.forEach((type) => {
    if (cache[type]) {
      logApp.debug('Reset cache for entity', { type, entityType });
      cache[type].values = undefined;
    } else {
      // This entity type is not part of the caching system
    }
  });
};

const handleCacheForEntity = async (instance: BasicStoreCommon, fn: string) => {
  const types = [instance.entity_type, ...(STORE_ENTITIES_LINKS[instance.entity_type] ?? [])];
  for (let index = 0; index < types.length; index += 1) {
    const type = types[index];
    if (cache[type]) {
      if (cache[type][fn]) {
        logApp.debug(`${fn} reset cache for entity`, { type, entityType: instance.entity_type });
        cache[type].values = await cache[type][fn](cache[type].values, instance);
      } else {
        logApp.debug('Simple reset cache for entity', { type, entityType: instance.entity_type });
        cache[type].values = undefined;
      }
    } else {
      // This entity type is not part of the caching system
    }
  }
};

export const removeCacheForEntity = async (instance: BasicStoreCommon) => {
  await handleCacheForEntity(instance, 'remove');
};

export const addCacheForEntity = async (instance: BasicStoreCommon) => {
  await handleCacheForEntity(instance, 'add');
};

export const refreshCacheForEntity = async (instance: BasicStoreCommon) => {
  await handleCacheForEntity(instance, 'refresh');
};

// not exported because mixes 2 types
// (map or array according to the data type storage in the cache)
// use either getEntitiesMapFromCache or getEntitiesListFromCache in export
const getEntitiesFromCache = async <T extends BasicStoreIdentifier | StixObject>(
  context: AuthContext, user: AuthUser, type: string
): Promise<Array<T> | Map<string, T>> => {
  const getEntitiesFromCacheFn = async (): Promise<Array<T> | Map<string, T>> => {
    const fromCache = cache[type];
    if (!fromCache) {
      throw UnsupportedError('Cache configuration type not supported', { type });
    }
    if (!fromCache.values) {
      // If cache already in progress build, just wait for completion
      if (fromCache.inProgress) {
        while (fromCache.inProgress) {
          await wait(100);
        }
        return fromCache.values ?? (type === ENTITY_TYPE_RESOLVED_FILTERS ? new Map() : []);
      }
      // If not in progress, re fetch the data
      fromCache.inProgress = true;
      try {
        fromCache.values = await fromCache.fn();
      } finally {
        fromCache.inProgress = false;
      }
    }
    return fromCache.values ?? (type === ENTITY_TYPE_RESOLVED_FILTERS ? new Map() : []);
  };
  return telemetry(context, user, `CACHE ${type}`, {
    [SEMATTRS_DB_NAME]: 'cache_engine',
    [SEMATTRS_DB_OPERATION]: 'select',
  }, getEntitiesFromCacheFn);
};

// get the list of the entities in the cache for a given type
export const getEntitiesListFromCache = async <T extends BasicStoreIdentifier | StixObject>(
  context: AuthContext, user: AuthUser, type: string
): Promise<Array<T>> => {
  if (type === ENTITY_TYPE_RESOLVED_FILTERS) {
    const map = await getEntitiesFromCache(context, user, type) as Map<string, T>;
    const result: T[] = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const value of map.values()) {
      result.push(value);
    }
    return result;
  }
  return await getEntitiesFromCache(context, user, type) as T[];
};

// get a map <id, instance> of the entities in the cache for a given type
export const getEntitiesMapFromCache = async <T extends BasicStoreIdentifier | StixObject>(
  context: AuthContext, user: AuthUser, type: string
): Promise<Map<string | StixId, T>> => {
  if (type === ENTITY_TYPE_RESOLVED_FILTERS) {
    return await getEntitiesFromCache(context, user, type) as Map<string, T>; // map of <standard_id, instance>
  }
  if (type === ENTITY_TYPE_PUBLIC_DASHBOARD) {
    const data = await getEntitiesFromCache(context, user, type) as BasicStoreEntityPublicDashboard[];
    return buildStorePublicDashboardMap(data); // map of <uri_key, instance>
  }
  const data = await getEntitiesFromCache(context, user, type) as BasicStoreIdentifier[];
  return buildStoreEntityMap(data); // map of <id, instance> for all the instance ids (internal_id, standard_id, stix ids)
};

export const getEntityFromCache = async <T extends BasicStoreIdentifier>(context: AuthContext, user: AuthUser, type: string): Promise<T> => {
  const data = await getEntitiesListFromCache<T>(context, user, type);
  return data[0];
};
