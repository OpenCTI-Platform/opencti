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
  type PaginateOpts,
  type ElFindByIdsOpts,
} from './engine-search';

// Import TiDB routing utilities
import {
  isTiDBEntityType,
  isTiDBSupportedFilter,
  elPaginateTiDB,
  elFindByIdsTiDB,
} from './engine-tidb';

// Re-export TiDB routing checks for use by middleware-loader (filter decisions)
export { isTiDBEntityType, isTiDBSupportedFilter } from './engine-tidb';

import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase, BasicConnection } from '../types/store';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';

// ---------------------------------------------------------------------------
// Routed: elPaginate
// ---------------------------------------------------------------------------

/**
 * Paginate entities — routes to TiDB for supported types, ES for the rest.
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

  if (entityTypes.length > 0 && isTiDBEntityType(entityTypes)) {
    const hasFilters = options.filters && isFilterGroupNotEmpty(options.filters);
    const canTiDBHandle = !hasFilters || isTiDBSupportedFilter(options.filters);
    if (canTiDBHandle) {
      return elPaginateTiDB<T>(context, user, indexName, {
        types: entityTypes,
        first: options.first,
        after: options.after as string | null | undefined,
        connectionFormat: options.connectionFormat,
        filters: hasFilters ? options.filters : undefined,
      });
    }
  }

  return elPaginateSearch<T>(context, user, indexName, options) as Promise<BasicConnection<T> | T[]>;
};

// ---------------------------------------------------------------------------
// Routed: elFindByIds
// ---------------------------------------------------------------------------

/**
 * Find entities by ID — routes to TiDB for supported types, ES for the rest.
 */
export const elFindByIds = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  ids: string[] | string,
  opts: ElFindByIdsOpts = {},
): Promise<T[] | Record<string, T>> => {
  if (opts?.type && isTiDBEntityType(opts.type)) {
    return elFindByIdsTiDB<T>(context, user, ids, { type: opts.type, toMap: opts.toMap, mapWithAllIds: opts.mapWithAllIds });
  }
  return elFindByIdsSearch<T>(context, user, ids, opts);
};

// ---------------------------------------------------------------------------
// Routed: elLoadById
// ---------------------------------------------------------------------------

/**
 * Load a single entity by ID — routes to TiDB for supported types, ES for the rest.
 */
export const elLoadById = async <T extends BasicStoreBase>(
  context: AuthContext,
  user: AuthUser,
  id: string,
  opts: { ignoreDuplicates?: boolean } & ElFindByIdsOpts = {},
) => {
  if (id && opts?.type && isTiDBEntityType(opts.type)) {
    const results = await elFindByIdsTiDB<T>(context, user, [id], { type: opts.type });
    return (results as T[])[0] as T;
  }
  return elLoadByIdSearch<T>(context, user, id, opts);
};
