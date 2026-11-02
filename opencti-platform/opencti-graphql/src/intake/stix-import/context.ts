import type { ImportClient, ImportLogger } from './types';

// State of one importer: pycti keeps it on its OpenCTIStix2 instance (mapping caches)
export interface ImportContext {
  readonly client: ImportClient;
  readonly logger: ImportLogger;
  // Draft of the operations; pycti suffixes its cache keys with it
  readonly draftId: string;
  // Short-lived cache (pycti mapping_cache, LRU of 50,000 entries)
  readonly cache: Map<string, any>;
  // Cache kept for the life of the importer (pycti mapping_cache_permanent)
  readonly permanentCache: Map<string, any>;
  // Reference time of the date guesses (pycti guess_past_date `now`); when unset, the current
  // time of each guess, as pycti
  readonly now?: Date;
}

export interface ImportContextOptions {
  draftId?: string;
  now?: Date;
}

const CACHE_SIZE = 50000;

export const createImportContext = (client: ImportClient, logger: ImportLogger, options: ImportContextOptions = {}): ImportContext => ({
  client,
  logger,
  draftId: options.draftId ?? '',
  cache: new Map(),
  permanentCache: new Map(),
  now: options.now,
});

export const getInCache = (context: ImportContext, key: string) => {
  const cacheKey = key + context.draftId;
  if (!context.cache.has(cacheKey)) {
    return null;
  }
  // Least recently used order, as pycti's LRUCache
  const value = context.cache.get(cacheKey);
  context.cache.delete(cacheKey);
  context.cache.set(cacheKey, value);
  return value;
};

export const setInCache = (context: ImportContext, key: string, value: any) => {
  const cacheKey = key + context.draftId;
  context.cache.delete(cacheKey);
  context.cache.set(cacheKey, value);
  if (context.cache.size > CACHE_SIZE) {
    context.cache.delete(context.cache.keys().next().value as string);
  }
};
