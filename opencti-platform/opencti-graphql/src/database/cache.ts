import * as R from 'ramda';
import { ATTR_DB_NAMESPACE, ATTR_DB_OPERATION_NAME, SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import type { BasicStoreCommon, BasicStoreIdentifier } from '../types/store';
import { logApp } from '../config/conf';
import { DatabaseError, UnsupportedError } from '../config/errors';
import { telemetry } from '../config/tracing';
import type { AuthContext, AuthUser } from '../types/user';
import type { StixId, StixObject } from '../types/stix-2-1-common';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../schema/internalObject';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../modules/dataSharing/streamCollection-types';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../schema/stixDomainObject';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { type BasicStoreEntityPublicDashboard, ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { ENTITY_TYPE_PIR } from '../modules/pir/pir-types';
import { ENTITY_TYPE_DECAY_EXCLUSION_RULE } from '../modules/decayRule/exclusions/decayExclusionRule-types';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { pushAll } from '../utils/arrayUtil';

export const STORE_ENTITIES_LINKS: Record<string, string[]> = {
  // Resolved Filters in cache must be reset depending on connector/stream/triggers/playbooks/Pir/label modifications
  [ENTITY_TYPE_STREAM_COLLECTION]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_TRIGGER]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_PLAYBOOK]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_CONNECTOR]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_PIR]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_DECAY_RULE]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_DECAY_EXCLUSION_RULE]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_LABEL]: [ENTITY_TYPE_RESOLVED_FILTERS],
  [ENTITY_TYPE_MARKING_DEFINITION]: [ENTITY_TYPE_RESOLVED_FILTERS],
  // Status must be reset depending on status template modifications
  [ENTITY_TYPE_STATUS_TEMPLATE]: [ENTITY_TYPE_STATUS],
};

const cache: any = {};

// Consecutive loads an invalidation may overtake before the waiting readers are served the last loaded values
// (without storing them), so a burst of invalidations cannot keep readers waiting until it ends.
export const MAX_CACHE_DISCARDS = 3;

/**
 * Drops the values of a cache entry and bumps its generation. A load in flight started before this
 * call reads the generation it was started with: when it finishes, it sees that an invalidation
 * overtook it and discards its result instead of storing data older than the invalidation.
 */
const invalidateCacheEntry = (entry: { values?: unknown; generation?: number }) => {
  // eslint-disable-next-line no-param-reassign
  entry.generation = (entry.generation ?? 0) + 1;
  // eslint-disable-next-line no-param-reassign
  entry.values = undefined;
};

const buildStoreEntityMap = <T extends BasicStoreIdentifier>(entities: Array<T>) => {
  const entityById = new Map();
  for (let i = 0; i < entities.length; i += 1) {
    const entity = entities[i];
    const ids = [entity.internal_id, ...(entity.x_opencti_stix_ids ?? [])];
    if (entity.standard_id) {
      ids.push(entity.standard_id);
    }
    if (entity.entity_type === ENTITY_TYPE_PUBLIC_DASHBOARD) {
      ids.push((entity as unknown as BasicStoreEntityPublicDashboard).uri_key);
    }
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
  const types = [entityType, ...(STORE_ENTITIES_LINKS[entityType] ?? [])];
  types.forEach((type) => {
    if (cache[type]) {
      logApp.debug('Reset cache for entity', { type, entityType });
      invalidateCacheEntry(cache[type]);
    } else {
      // This entity type is not part of the caching system
    }
  });
};

const handleCacheForEntity = async (instance: BasicStoreCommon | BasicStoreCommon[], fn: string) => {
  const instances = Array.isArray(instance) ? instance : [instance];
  const types = R.uniq(instances.map((i) => [i.entity_type, ...(STORE_ENTITIES_LINKS[i.entity_type] ?? [])]).flat());
  for (let index = 0; index < types.length; index += 1) {
    const type = types[index];
    if (cache[type] && cache[type].values) {
      if (cache[type][fn]) {
        logApp.debug(`${fn} reset cache for entity`, { type });
        const entry = cache[type];
        const handler = entry[fn];
        const applyHandler = async () => {
          if (!entry.values) {
            // Invalidated while the previous handler ran: nothing to update, the next read loads again.
            return;
          }
          const startGeneration = entry.generation ?? 0;
          const values = await handler(entry.values, instance);
          if ((entry.generation ?? 0) !== startGeneration) {
            // Invalidated during the handler: its values may predate the invalidation, leave the entry cleared.
            logApp.debug('[CACHE] Cache invalidated during an incremental update, discarding its values', { type, fn });
            return;
          }
          entry.values = values;
        };
        // The handlers of an entry run one after another, each on the values the previous one stored:
        // two concurrent handlers started from the same values would each drop the other's update.
        const applying = (entry.updating ?? Promise.resolve()).then(applyHandler);
        entry.updating = applying.catch(() => undefined);
        await applying;
      } else {
        logApp.debug('Simple reset cache for entity', { type });
        invalidateCacheEntry(cache[type]);
      }
    } else if (cache[type]) {
      // Not loaded yet, or a load is in flight: that load may have read the data before this change,
      // so it must not be stored (it would hide the change until the next invalidation).
      invalidateCacheEntry(cache[type]);
    } else {
      // This entity type is not part of the caching system
    }
  }
};

export const removeCacheForEntity = async (instance: BasicStoreCommon | BasicStoreCommon[]) => {
  await handleCacheForEntity(instance, 'remove');
};

export const addCacheForEntity = async (instance: BasicStoreCommon | BasicStoreCommon[]) => {
  await handleCacheForEntity(instance, 'add');
};

export const refreshCacheForEntity = async (instance: BasicStoreCommon | BasicStoreCommon[]) => {
  await handleCacheForEntity(instance, 'refresh');
};

export const refreshLocalCacheForEntity = async (topic: string, instance: BasicStoreCommon | BasicStoreCommon[]) => {
  if (topic.endsWith('EDIT_TOPIC')) {
    await refreshCacheForEntity(instance);
  }
  if (topic.endsWith('ADDED_TOPIC')) {
    await addCacheForEntity(instance);
  }
  if (topic.endsWith('DELETE_TOPIC')) {
    await removeCacheForEntity(instance);
  }
};

// not exported because mixes 2 types
// (map or array according to the data type storage in the cache)
// use either getEntitiesMapFromCache or getEntitiesListFromCache in export
const getEntitiesFromCache = async <T extends BasicStoreIdentifier | StixObject>(
  context: AuthContext, user: AuthUser, type: string,
): Promise<Array<T> | Map<string, T>> => {
  const getEntitiesFromCacheFn = async (): Promise<Array<T> | Map<string, T>> => {
    const fromCache = cache[type];
    if (!fromCache) {
      throw UnsupportedError('Cache configuration type not supported', { type });
    }
    const MAX_CACHE_RETRIES = 10;
    let retries = 0;
    // Loop until values are available.
    // If a concurrent fetch fails, waiters retry instead of returning empty data.
    while (!fromCache.values) {
      if (!fromCache.inProgress) {
        const startGeneration = fromCache.generation ?? 0;
        // Resolves with the values to serve without storing them (discard cap reached), undefined otherwise
        const loadFromFn = async (): Promise<unknown> => {
          try {
            let cacheData = await fromCache.fn();
            if (!cacheData) {
              // This situation must be adapted with code evolution
              logApp.warn('[CACHE] Cache function refresh return undefined values', { type });
              cacheData = type === ENTITY_TYPE_RESOLVED_FILTERS ? new Map() : [];
            }
            if ((fromCache.generation ?? 0) !== startGeneration) {
              // Invalidated while loading: the data may predate the change, never store it.
              fromCache.discards = (fromCache.discards ?? 0) + 1;
              if (fromCache.discards >= MAX_CACHE_DISCARDS) {
                // Serve the waiting readers, the next read loads again.
                logApp.warn('[CACHE] Cache invalidated during consecutive loads, serving the loaded values without storing them', { type, discards: fromCache.discards });
                fromCache.discards = 0;
                return cacheData;
              }
              logApp.debug('[CACHE] Cache invalidated while loading, discarding the loaded values', { type, discards: fromCache.discards });
              return undefined;
            }
            fromCache.discards = 0;
            fromCache.values = cacheData;
            return undefined;
          } finally {
            fromCache.inProgress = undefined;
          }
        };
        fromCache.inProgress = loadFromFn();
      }

      try {
        const served = await fromCache.inProgress;
        if (served !== undefined) {
          return served as Array<T> | Map<string, T>;
        }
      } catch (err: any) {
        retries += 1;
        logApp.error('[CACHE] Error loading cache', { type, attempt: retries, maxRetries: MAX_CACHE_RETRIES, cause: err });
        if (retries >= MAX_CACHE_RETRIES) {
          throw DatabaseError(err.message);
        }
      }
    }
    return fromCache.values as Promise<Array<T> | Map<string, T>>;
  };
  return telemetry(context, user, `CACHE ${type}`, {
    [ATTR_DB_NAMESPACE]: 'cache_engine',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_NAME]: 'cache_engine',
    [ATTR_DB_OPERATION_NAME]: 'select',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_OPERATION]: 'select',
  }, getEntitiesFromCacheFn);
};

// get the list of the entities in the cache for a given type
export const getEntitiesListFromCache = async <T extends BasicStoreIdentifier | StixObject>(
  context: AuthContext, user: AuthUser, type: string,
): Promise<Array<T>> => {
  const data = await getEntitiesFromCache(context, user, type);
  if (type === ENTITY_TYPE_RESOLVED_FILTERS) {
    const result: T[] = [];
    pushAll(result, (data as Map<string, T>).values());
    return result;
  }
  return data as T[];
};

// get a map <id, instance> of the entities in the cache for a given type
export const getEntitiesMapFromCache = async <T extends BasicStoreIdentifier | StixObject>(
  context: AuthContext, user: AuthUser, type: string,
): Promise<Map<string | StixId, T>> => {
  const data = await getEntitiesFromCache(context, user, type);
  // Filters is already a map
  if (type === ENTITY_TYPE_RESOLVED_FILTERS) {
    return data as Map<string, T>; // map of <standard_id, instance>
  }
  return buildStoreEntityMap(data as BasicStoreIdentifier[]); // map of <id, instance> for all the instance ids (internal_id, standard_id, stix ids)
};

export const getEntityFromCache = async <T extends BasicStoreIdentifier>(context: AuthContext, user: AuthUser, type: string): Promise<T> => {
  const data = await getEntitiesListFromCache<T>(context, user, type);
  return data[0];
};
