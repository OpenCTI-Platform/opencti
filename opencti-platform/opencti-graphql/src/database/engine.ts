/**
 * engine.ts — Search engine router.
 *
 * Thin routing layer that delegates read queries to either:
 * - engine-tidb.ts (opencti-ng REST API) for entity types stored in TiDB
 * - engine-search.ts (Elasticsearch/OpenSearch) for everything else
 *
 * All other exports (write operations, index management, constants, etc.)
 * are re-exported from engine-search.ts unchanged.
 */

// Re-export everything from the search engine (Elasticsearch/OpenSearch).
// Local exports below override the wildcard for routed functions.
export * from './engine-search';

// Import the search-engine versions of functions we override
import {
  elPaginate as elPaginateSearch,
  elFindByIds as elFindByIdsSearch,
  elLoadById as elLoadByIdSearch,
  elList as elListSearch,
  type PaginateOpts,
  type ElFindByIdsOpts,
  type RepaginateOpts,
} from './engine-search';

// Import TiDB routing utilities
import { elPaginateTiDB, elFindByIdsTiDB, elListTiDB } from './engine-tidb';

// Re-export TiDB routing checks for use by middleware-loader (filter decisions)
export { isTiDBEntityType } from './engine-tidb';

import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase, BasicConnection } from '../types/store';
import { isInternalObject } from '../schema/internalObject';
import { isInternalRelationship } from '../schema/internalRelationship';

// ---------------------------------------------------------------------------
// Internal type check — internal objects/relationships are NOT in TiDB
// ---------------------------------------------------------------------------

const isInternalType = (type: string): boolean => {
  return isInternalObject(type) || isInternalRelationship(type);
};

const hasOnlyInternalTypes = (types: string | string[] | null | undefined): boolean => {
  if (!types) return false;
  const arr = Array.isArray(types) ? types : [types];
  return arr.length > 0 && arr.every(isInternalType);
};

// ---------------------------------------------------------------------------
// Routed: elPaginate
// ---------------------------------------------------------------------------

/**
 * Paginate entities — tries TiDB first (all non-internal types), then
 * falls back to Elasticsearch if nothing found.
 */
export const elPaginate = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined | null,
  options: PaginateOpts = {},
): Promise<BasicConnection<T> | T[]> => {
  const { types } = options;
  const entityTypes = types
    ? (Array.isArray(types) ? types : [types])
    : [];

  // If explicitly internal types, skip TiDB entirely
  if (entityTypes.length > 0 && entityTypes.every(isInternalType)) {
    return elPaginateSearch<T>(context, user, indexName, options) as Promise<BasicConnection<T> | T[]>;
  }

  // Try TiDB first if filters are supported
  const tidbResult = await elPaginateTiDB<T>(context, user, indexName, {
    types: entityTypes.length > 0 ? entityTypes : undefined,
    first: options.first,
    after: options.after as string | null | undefined,
    connectionFormat: options.connectionFormat,
    filters: options.filters,
  });

  // Check if we got results
  const hasResults = options.connectionFormat === false
    ? (tidbResult as T[]).length > 0
    : ((tidbResult as BasicConnection<T>).edges?.length ?? 0) > 0;

  if (hasResults) return tidbResult;

  // Fallback to ES
  return elPaginateSearch<T>(context, user, indexName, options) as Promise<BasicConnection<T> | T[]>;
};

// ---------------------------------------------------------------------------
// Routed: elFindByIds
// ---------------------------------------------------------------------------

/**
 * Find entities by ID — tries TiDB first (all non-internal types), then
 * falls back to Elasticsearch if nothing found.
 */
export const elFindByIds = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  ids: string[] | string,
  opts: ElFindByIdsOpts = {},
): Promise<T[] | Record<string, T>> => {
  // If the caller explicitly asks for internal types, skip TiDB entirely
  if (hasOnlyInternalTypes(opts.type)) {
    return elFindByIdsSearch<T>(context, user, ids, opts);
  }

  // Try TiDB first (handles all STIX types)
  const tidbResult = await elFindByIdsTiDB<T>(context, user, ids, {
    type: opts.type,
    toMap: opts.toMap,
    mapWithAllIds: opts.mapWithAllIds,
  });

  // Check if we got results
  const tidbHasResults = opts.toMap
    ? Object.keys(tidbResult as Record<string, T>).length > 0
    : (tidbResult as T[]).length > 0;

  if (tidbHasResults) {
    return tidbResult;
  }

  // No results from TiDB — fallback to ES
  return elFindByIdsSearch<T>(context, user, ids, opts);
};

// ---------------------------------------------------------------------------
// Routed: elLoadById
// ---------------------------------------------------------------------------

/**
 * Load a single entity by ID — tries TiDB first, falls back to ES.
 */
export const elLoadById = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  opts: { ignoreDuplicates?: boolean } & ElFindByIdsOpts = {},
) => {
  if (!id) return undefined;

  // If explicitly internal, go to ES directly
  if (opts?.type && hasOnlyInternalTypes(opts.type)) {
    return elLoadByIdSearch<T>(context, user, id, opts);
  }

  // Try TiDB first
  const results = await elFindByIdsTiDB<T>(context, user, [id], { type: opts.type });
  const found = (results as T[])[0];
  if (found) return found;

  // Fallback to ES
  return elLoadByIdSearch<T>(context, user, id, opts);
};

// ---------------------------------------------------------------------------
// Routed: elList
// ---------------------------------------------------------------------------

/**
 * List all entities matching criteria — tries TiDB first (no repagination
 * needed: TiDB handles large offsets natively), falls back to ES.
 */
export const elList = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  indexName: string | string[] | undefined | null,
  opts: RepaginateOpts<T> = {},
): Promise<T[]> => {
  const { types } = opts;
  const entityTypes = types
    ? (Array.isArray(types) ? types : [types])
    : [];

  // If explicitly internal types, skip TiDB entirely
  if (entityTypes.length > 0 && entityTypes.every(isInternalType)) {
    return elListSearch<T>(context, user, indexName, opts);
  }

  // Try TiDB first — directly via elPaginateTiDB, no repagination
  const tidbResult = await elListTiDB<T>(context, user, indexName, {
    types: entityTypes.length > 0 ? entityTypes : undefined,
    first: opts.first ?? 500,
    filters: opts.filters,
    maxSize: opts.maxSize,
    callback: opts.callback,
  });

  if (tidbResult.length > 0) return tidbResult;

  // Fallback to ES (with repagination)
  return elListSearch<T>(context, user, indexName, opts);
};

// ---------------------------------------------------------------------------
// Routed: elBatchIds / elBatchIdsWithRelCount
// ---------------------------------------------------------------------------
// The versions in engine-search.ts call their own module's elFindByIds
// (ES-only). These overrides use the routed elFindByIds above so that
// TiDB entity types are resolved via the opencti-ng API.

/**
 * Batch-load entities by ID — uses the routed elFindByIds so TiDB types
 * are fetched from opencti-ng instead of Elasticsearch.
 */
export const elBatchIds = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  elements: { id: string; type: string }[],
) => {
  const ids = elements.map((e) => e.id);
  const types = elements.map((e) => e.type);
  const mapHits = await elFindByIds<T>(context, user, ids, { type: types, toMap: true }) as Record<string, T>;
  return ids.map((id) => mapHits[id]);
};

/**
 * Batch-load entities by ID with relationship count — uses the routed
 * elFindByIds so TiDB entity types are fetched from opencti-ng.
 */
export const elBatchIdsWithRelCount = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  elements: { id: string; type: string }[],
) => {
  const ids = elements.map((e) => e.id);
  const types = elements.map((e) => e.type);
  const hits = await elFindByIds<T>(context, user, ids, { type: types, baseData: true }) as T[];
  return ids.map((id) => hits.find((h: any) => h.internal_id === id));
};
