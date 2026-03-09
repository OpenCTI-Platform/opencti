/**
 * engine-tidb.ts — OpenCTI-NG REST API client for reading entities.
 *
 * Drop-in replacement for the Elasticsearch functions `elPaginate` and `elFindByIds`
 * for entity types that live in TiDB via the opencti-ng Rust backend.
 *
 * Calls the opencti-ng REST API (e.g. GET /api/v1/organizations) and transforms
 * the response into the same BasicStoreEntity / BasicConnection shapes that the
 * existing Elasticsearch engine returns, so the middleware/resolver stack works
 * without changes.
 */

import { offsetToCursor, buildPaginationFromEdges } from './utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase, BasicConnection, BasicNodeEdge } from '../types/store';
import conf, { logApp } from '../config/conf';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const getBaseUrl = (): string => {
  return conf.get('opencti_ng:url') || 'http://127.0.0.1:4100';
};

const getApiToken = (): string => {
  return conf.get('opencti_ng:token') || '';
};

// ---------------------------------------------------------------------------
// Entity type mapping
// ---------------------------------------------------------------------------

const TIDB_SUPPORTED_TYPES = new Set([
  'Organization', 'Sector',
  'Region', 'Country', 'City', 'Position',
  'Location',
]);

export const isTiDBEntityType = (entityType: string | string[]): boolean => {
  const types = Array.isArray(entityType) ? entityType : [entityType];
  return types.every((t) => TIDB_SUPPORTED_TYPES.has(t));
};

/** Map OpenCTI entity type to the opencti-ng REST API resource path. */
const typeToApiPath = (entityType: string): string => {
  switch (entityType) {
    case 'Organization': return 'organizations';
    case 'Sector': return 'sectors';
    case 'Region': return 'regions';
    case 'Country': return 'countries';
    case 'City': return 'cities';
    case 'Position': return 'positions';
    case 'Location': return 'locations';
    default:
      return entityType.toLowerCase();
  }
};

/** Map opencti-ng REST API resource path back to OpenCTI entity type. */
const apiPathToType = (apiPath: string): string => {
  switch (apiPath) {
    case 'organizations': return 'Organization';
    case 'sectors': return 'Sector';
    case 'regions': return 'Region';
    case 'countries': return 'Country';
    case 'cities': return 'City';
    case 'positions': return 'Position';
    case 'locations': return 'Location';
    default: return apiPath;
  }
};

// Parent types hierarchy (mirrors OpenCTI schema)
const PARENT_TYPES: Record<string, string[]> = {
  Organization: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Identity'],
  Sector: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Identity'],
  Region: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Location'],
  Country: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Location'],
  City: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Location'],
  Position: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Location'],
};

// ---------------------------------------------------------------------------
// Filter support
// ---------------------------------------------------------------------------

/**
 * Check if a FilterGroup contains only filters that TiDB/opencti-ng can handle.
 * Currently supports: regardingOf filters (used by sector parent/child queries).
 */
export const isTiDBSupportedFilter = (filterGroup: any): boolean => {
  if (!filterGroup) return true;
  const { filters = [], filterGroups = [] } = filterGroup;
  // All top-level filters must be regardingOf
  for (const filter of filters) {
    const keys = filter.key || [];
    if (!keys.includes('regardingOf')) {
      return false;
    }
  }
  // Recursively check nested groups
  for (const group of filterGroups) {
    if (!isTiDBSupportedFilter(group)) {
      return false;
    }
  }
  return true;
};

/**
 * Serialize an OpenCTI FilterGroup for the opencti-ng REST API query parameter.
 */
const serializeFiltersForTiDB = (filterGroup: any): string => {
  return JSON.stringify(filterGroup);
};

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

interface ApiListResponse {
  data: Record<string, any>[];
  total: number;
}

const apiGet = async <T>(path: string, token: string): Promise<T> => {
  const url = `${getBaseUrl()}/api/v1/${path}`;
  logApp.debug('[ENGINE-TIDB] GET', { url });
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`opencti-ng API error ${response.status}: ${body}`);
  }
  return response.json() as Promise<T>;
};

// ---------------------------------------------------------------------------
// opencti-ng entity → BasicStoreEntity converter
// ---------------------------------------------------------------------------

/**
 * Convert an opencti-ng API entity into a BasicStoreEntity-compatible object
 * matching what Elasticsearch would return (with denormalized rel_ fields).
 */
const apiEntityToStoreEntity = (
  entity: Record<string, any>,
  openctiType: string,
): Record<string, any> => {
  const internalId = entity.internal_id;
  const standardId = entity.standard_id;

  // For locations, determine the effective entity_type
  let entityType = openctiType;
  if (openctiType === 'Location' && entity.x_opencti_location_type) {
    entityType = entity.x_opencti_location_type; // Region, Country, etc.
  }

  const parentTypes = PARENT_TYPES[entityType]
    || ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'];

  // Extract stix_ids from identifiers
  const stixIds = (entity.identifiers || [])
    .filter((i: any) => i.identifier_type === 'stix_id')
    .map((i: any) => i.identifier_value);

  // Extract marking internal_ids from object_markings
  const markingIds = (entity.object_markings || [])
    .map((om: any) => om.marking?.standard_id)
    .filter(Boolean);

  // Extract label internal_ids from labels
  const labelIds = (entity.labels || [])
    .map((l: any) => l.id)
    .filter(Boolean);

  const store: Record<string, any> = {
    _index: 'opencti-ng',
    _id: internalId,
    id: internalId,
    internal_id: internalId,
    standard_id: standardId,
    entity_type: entityType,
    base_type: 'ENTITY',
    parent_types: parentTypes,
    spec_version: '2.1',
    created_at: entity.created,
    updated_at: entity.modified,
    created: entity.created,
    modified: entity.modified,
    name: entity.name || '',
    description: entity.description ?? '',
    confidence: entity.confidence ?? 0,
    revoked: entity.revoked ?? false,
    lang: 'en',
    x_opencti_stix_ids: stixIds,
    representative: {
      main: entity.representative?.main ?? entity.name ?? '',
      secondary: entity.representative?.secondary ?? entity.description ?? '',
    },
  };

  // Denormalized relationship refs (same shape as ES engine returns)
  if (markingIds.length > 0) {
    store['rel_object-marking.internal_id'] = markingIds;
  }
  if (labelIds.length > 0) {
    store['rel_object-label.internal_id'] = labelIds;
  }
  if (entity.created_by_ref) {
    store['rel_created-by.internal_id'] = entity.created_by_ref;
  }

  // Identity-specific
  if (entityType === 'Organization' || entityType === 'Sector') {
    store.identity_class = entityType.toLowerCase();
  }

  // Organization-specific
  if (entity.contact_information !== undefined) {
    store.contact_information = entity.contact_information;
  }
  if (entity.organization_type !== undefined) {
    store.x_opencti_organization_type = entity.organization_type;
  }

  // Sector-specific
  if (entity.x_opencti_aliases) {
    store.x_opencti_aliases = entity.x_opencti_aliases;
  }

  // Location-specific
  if (entity.latitude !== undefined) store.latitude = entity.latitude;
  if (entity.longitude !== undefined) store.longitude = entity.longitude;
  if (entity.x_opencti_location_type !== undefined) {
    store.x_opencti_location_type = entity.x_opencti_location_type;
  }
  if (entity.region !== undefined) store.region = entity.region;
  if (entity.country !== undefined) store.country = entity.country;

  return store;
};

// ---------------------------------------------------------------------------
// Public API — elPaginate (via opencti-ng REST)
// ---------------------------------------------------------------------------

export interface TiDBPaginateOpts {
  types?: string[] | string | null;
  first?: number;
  after?: string | null;
  orderBy?: any;
  orderMode?: 'asc' | 'desc' | null;
  search?: string | null;
  connectionFormat?: boolean;
  filters?: any;
}

/**
 * Paginate entities via the opencti-ng REST API.
 *
 * Returns a `BasicConnection<T>` when `connectionFormat` is true (default),
 * or `T[]` when false.
 */
export const elPaginateTiDB = async <T extends BasicStoreBase>(
  _context: AuthContext,
  _user: AuthUser,
  _indexName: string | string[] | undefined | null,
  options: TiDBPaginateOpts = {},
): Promise<BasicConnection<T> | T[]> => {
  const {
    types = null,
    first = 25,
    after = null,
    connectionFormat = true,
  } = options;

  const entityTypes = types
    ? (Array.isArray(types) ? types : [types])
    : ['Organization'];

  // Decode cursor → offset
  let offset = 0;
  if (after) {
    try {
      const decoded = JSON.parse(Buffer.from(after, 'base64').toString('utf-8'));
      offset = typeof decoded === 'number' ? decoded : (Array.isArray(decoded) ? decoded[0] : 0);
    } catch {
      offset = 0;
    }
  }

  const token = getApiToken();

  // Group requests by API path (e.g., organizations, sectors, locations)
  const pathGroups = new Map<string, string[]>();
  for (const t of entityTypes) {
    const path = typeToApiPath(t);
    if (!pathGroups.has(path)) pathGroups.set(path, []);
    pathGroups.get(path)!.push(t);
  }

  let allEntities: Record<string, any>[] = [];
  let totalCount = 0;

  // Fetch from each API path
  for (const [apiPath, groupTypes] of Array.from(pathGroups)) {
    const queryParams = new URLSearchParams({
      limit: String(first),
      offset: String(offset),
    });

    // Pass filters through to opencti-ng as a JSON query parameter
    if (options.filters) {
      queryParams.set('filters', serializeFiltersForTiDB(options.filters));
    }

    const result = await apiGet<ApiListResponse>(
      `${apiPath}?${queryParams.toString()}`,
      token,
    );

    // Use the reverse mapping to get the opencti type
    const openctiType = apiPathToType(apiPath);

    const entities = result.data.map((e) => apiEntityToStoreEntity(e, openctiType));
    allEntities.push(...entities);

    totalCount += result.total;
  }

  const typedEntities = allEntities as T[];

  if (!connectionFormat) {
    return typedEntities;
  }

  // Build edges with offset-based cursors
  const edges: BasicNodeEdge<T>[] = typedEntities.map((entity, i) => ({
    node: entity,
    cursor: offsetToCursor([offset + i]),
  }));

  return buildPaginationFromEdges<T>(first, after, edges, totalCount);
};

// ---------------------------------------------------------------------------
// Public API — elFindByIds (via opencti-ng REST)
// ---------------------------------------------------------------------------

export interface TiDBFindByIdsOpts {
  type?: string | string[] | null;
  toMap?: boolean;
  mapWithAllIds?: boolean;
  baseData?: boolean;
  withoutRels?: boolean;
}

/**
 * Find entities by ID via the opencti-ng REST API.
 *
 * Fetches each entity individually by its internal UUID via GET /{resource}/{id}.
 * Returns T[] by default, or Record<string, T> if toMap is true.
 */
export const elFindByIdsTiDB = async <T extends BasicStoreBase>(
  _context: AuthContext,
  _user: AuthUser,
  ids: string[] | string,
  opts: TiDBFindByIdsOpts = {},
): Promise<T[] | Record<string, T>> => {
  const { type = null, toMap = false, mapWithAllIds = false } = opts;

  const idsArray = Array.isArray(ids) ? ids : [ids];
  const processIds = idsArray.filter((id) => id != null && id !== '');
  if (processIds.length === 0) {
    return toMap ? {} as Record<string, T> : [] as T[];
  }

  const entityTypes = type
    ? (Array.isArray(type) ? type : [type])
    : Array.from(TIDB_SUPPORTED_TYPES);

  const token = getApiToken();

  // For each ID, try fetching from each possible API path until found
  const apiPaths = Array.from(new Set(entityTypes.map(typeToApiPath)));
  const entities: T[] = [];

  for (const id of processIds) {
    let found = false;
    for (const apiPath of apiPaths) {
      try {
        const entity = await apiGet<Record<string, any>>(
          `${apiPath}/${id}`,
          token,
        );
        // Determine the opencti type for conversion
        const openctiType = apiPathToType(apiPath);
        const storeEntity = apiEntityToStoreEntity(entity, openctiType) as T;
        entities.push(storeEntity);
        found = true;
        break;
      } catch {
        // Not found on this path — try next
        continue;
      }
    }
    if (!found) {
      logApp.debug('[ENGINE-TIDB] Entity not found', { id });
    }
  }

  if (toMap) {
    const map: Record<string, T> = {};
    for (const entity of entities) {
      const e = entity as any;
      map[e.internal_id] = entity;
      if (mapWithAllIds) {
        if (e.standard_id) map[e.standard_id] = entity;
        if (e.x_opencti_stix_ids) {
          for (const sid of e.x_opencti_stix_ids) {
            map[sid] = entity;
          }
        }
      }
    }
    return map;
  }

  return entities;
};
