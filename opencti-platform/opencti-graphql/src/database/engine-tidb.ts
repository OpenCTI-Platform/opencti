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
  'Malware',
  'Attack-Pattern', 'Intrusion-Set', 'Campaign', 'Tool', 'Course-Of-Action',
  'Vulnerability',
  'Report',
]);

export const isTiDBEntityType = (entityType: string | string[]): boolean => {
  const types = Array.isArray(entityType) ? entityType : [entityType];
  return types.every((t) => TIDB_SUPPORTED_TYPES.has(t));
};

/** Map OpenCTI entity type to the opencti-ng REST API resource path. */
const typeToApiPath = (entityType: string): string => {
  switch (entityType) {
    // SDO — Identity subtypes
    case 'Organization': return 'organizations';
    case 'Sector': return 'sectors';
    case 'Individual': return 'individuals';
    case 'System': return 'systems';
    case 'Security-Platform': return 'security-platforms';
    // SDO — Location subtypes (all served from /locations endpoint)
    case 'Region': return 'regions';
    case 'Country': return 'countries';
    case 'City': return 'cities';
    case 'Position': return 'positions';
    case 'Administrative-Area': return 'administrative-areas';
    case 'Location': return 'locations';
    // SDO — Core types
    case 'Malware': return 'malware';
    case 'Attack-Pattern': return 'attack-patterns';
    case 'Intrusion-Set': return 'intrusion-sets';
    case 'Campaign': return 'campaigns';
    case 'Tool': return 'tools';
    case 'Course-Of-Action': return 'courses-of-action';
    case 'Vulnerability': return 'vulnerabilities';
    case 'Indicator': return 'indicators';
    case 'Infrastructure': return 'infrastructures';
    case 'Incident': return 'incidents';
    case 'Data-Source': return 'data-sources';
    case 'Data-Component': return 'data-components';
    case 'Malware-Analysis': return 'malware-analyses';
    case 'Software': return 'software';
    case 'Channel': return 'channels';
    case 'Narrative': return 'narratives';
    case 'Event': return 'events';
    // SDO — Threat actors
    case 'Threat-Actor-Group': return 'threat-actor-groups';
    case 'Threat-Actor-Individual': return 'threat-actor-individuals';
    // SDO — Containers
    case 'Report': return 'reports';
    case 'Note': return 'notes';
    case 'Opinion': return 'opinions';
    case 'Observed-Data': return 'observed-data';
    case 'Grouping': return 'groupings';
    case 'Case-Incident': return 'case-incidents';
    case 'Case-Rfi': return 'case-rfis';
    case 'Case-Rft': return 'case-rfts';
    case 'Feedback': return 'feedbacks';
    case 'Task': return 'tasks';
    // SRO
    case 'Relationship':
    case 'stix-core-relationship': return 'relationships';
    case 'stix-sighting-relationship': return 'sightings';
    // SCO
    case 'IPv4-Addr': return 'ipv4-addrs';
    case 'IPv6-Addr': return 'ipv6-addrs';
    case 'Domain-Name': return 'domain-names';
    case 'Url': return 'urls';
    case 'Email-Addr': return 'email-addrs';
    case 'Email-Message': return 'email-messages';
    case 'Artifact': return 'artifacts';
    case 'Autonomous-System': return 'autonomous-systems';
    case 'StixFile': return 'stix-files';
    case 'Directory': return 'directories';
    case 'Process': return 'processes';
    case 'User-Account': return 'user-accounts';
    case 'Network-Traffic': return 'network-traffic';
    case 'Windows-Registry-Key': return 'windows-registry-keys';
    case 'X509-Certificate': return 'x509-certificates';
    case 'Mac-Addr': return 'mac-addrs';
    case 'Hostname': return 'hostnames';
    case 'Credential': return 'credentials';
    case 'Tracking-Number': return 'tracking-numbers';
    case 'Bank-Account': return 'bank-accounts';
    case 'Payment-Card': return 'payment-cards';
    case 'Media-Content': return 'media-contents';
    case 'Phone-Number': return 'phone-numbers';
    case 'Mutex': return 'mutexes';
    case 'Text': return 'texts';
    case 'Cryptocurrency-Wallet': return 'cryptocurrency-wallets';
    case 'Cryptographic-Key': return 'cryptographic-keys';
    case 'User-Agent': return 'user-agents';
    default:
      return entityType.toLowerCase();
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
  'Administrative-Area': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Location'],
  Malware: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  'Attack-Pattern': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  'Intrusion-Set': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  Campaign: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  Tool: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  'Course-Of-Action': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  Vulnerability: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  Report: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Container'],
  Relationship: ['Basic-Relationship', 'Stix-Relationship', 'Stix-Core-Relationship'],
  Sighting: ['Basic-Relationship', 'Stix-Relationship', 'Stix-Sighting-Relationship'],
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

const apiPost = async <T>(path: string, body: Record<string, any>, token: string): Promise<T> => {
  const url = `${getBaseUrl()}/api/v1/${path}`;
  logApp.debug('[ENGINE-TIDB] POST', { url });
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const bodyText = await response.text().catch(() => '');
    throw new Error(`opencti-ng API error ${response.status}: ${bodyText}`);
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
  const internalId = entity.internal_id || entity.id;
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
  if (entity.organization_type !== undefined) {
    store.x_opencti_organization_type = entity.organization_type;
  }

  // Relationship-specific: map source_ref/target_ref → fromId/toId
  if (entity.source_ref) {
    store.fromId = entity.source_ref;
    store.toId = entity.target_ref;
    store.fromType = entity.source_type || 'Unknown';
    store.toType = entity.target_type || 'Unknown';
    store.relationship_type = entity.relationship_type;
    store.base_type = 'RELATION';
    if (entity.start_time) store.start_time = entity.start_time;
    if (entity.stop_time) store.stop_time = entity.stop_time;
  }

  return { ...entity, ...store };
};

/**
 * Convert a lightweight Element (from POST /api/v1/stix/elements) into a
 * BasicStoreEntity-compatible object. Uses the parent_types returned by the
 * API directly, avoiding client-side hierarchy duplication.
 */
const elementToStoreEntity = (
  element: Record<string, any>,
): Record<string, any> => {
  const internalId = element.internal_id;
  const entityType = element.entity_type;

  // Use parent_types from the API response directly, prepend Basic-Object + Stix-Object
  const apiParentTypes: string[] = element.parent_types || [];
  const parentTypes = ['Basic-Object', 'Stix-Object', ...apiParentTypes];

  // Extract stix_ids from identifiers
  const stixIds = (element.identifiers || [])
    .filter((i: any) => i.identifier_type === 'stix_id')
    .map((i: any) => i.identifier_value);

  return {
    _index: 'opencti-ng',
    _id: internalId,
    id: internalId,
    internal_id: internalId,
    standard_id: element.standard_id,
    entity_type: entityType,
    base_type: 'ENTITY',
    parent_types: parentTypes,
    spec_version: '2.1',
    created_at: element.created,
    updated_at: element.modified,
    created: element.created,
    modified: element.modified,
    name: element.name || '',
    description: element.description ?? '',
    confidence: element.confidence ?? 0,
    revoked: element.revoked ?? false,
    lang: 'en',
    x_opencti_stix_ids: stixIds,
    representative: {
      main: element.representative?.main ?? element.name ?? '',
      secondary: element.representative?.secondary ?? element.description ?? '',
    },
  };
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

  // Detect concrete relationship types (all-lowercase types like 'uses',
  // 'targets', 'originates-from' that aren't in typeToApiPath's switch).
  // These route to /api/v1/relationships?type=<rel_type> instead of
  // generating per-type paths that don't exist.
  const isConcreteRelType = (t: string): boolean => {
    // Abstract relationship types are already handled by typeToApiPath
    if (t === 'stix-core-relationship' || t === 'Relationship'
      || t === 'stix-sighting-relationship' || t === 'Sighting') return false;
    // Entity types are PascalCase (start with uppercase)
    // Concrete relationship types are all lowercase (uses, targets, originates-from)
    return t.charAt(0) === t.charAt(0).toLowerCase();
  };

  // Group requests by API path (e.g., organizations, sectors, locations)
  // Concrete relationship types get unique keys to avoid merging
  const pathGroups = new Map<string, { apiPath: string; relType?: string }>();
  for (const t of entityTypes) {
    if (isConcreteRelType(t)) {
      const key = `relationships:${t}`;
      pathGroups.set(key, { apiPath: 'relationships', relType: t });
    } else {
      const path = typeToApiPath(t);
      if (!pathGroups.has(path)) pathGroups.set(path, { apiPath: path });
    }
  }

  const allEntities: Record<string, any>[] = [];
  let totalCount = 0;

  // Fetch from each API path
  for (const [_, { apiPath, relType }] of Array.from(pathGroups)) {
    const queryParams = new URLSearchParams({
      limit: String(first),
      offset: String(offset),
    });

    // For concrete relationship types, add type filter
    if (relType) {
      queryParams.set('type', relType);
    }

    // Pass filters through to opencti-ng as a JSON query parameter
    if (options.filters) {
      queryParams.set('filters', serializeFiltersForTiDB(options.filters));
    }

    const result = await apiGet<ApiListResponse>(
      `${apiPath}?${queryParams.toString()}`,
      token,
    );

    // Use entity_type from the API response directly (correct casing from DB)
    const entities = result.data.map((e) => apiEntityToStoreEntity(e, e.entity_type));
    allEntities.push(...entities);

    totalCount += result.total;
  }

  const typedEntities = allEntities as T[];

  if (!connectionFormat) {
    return typedEntities;
  }

  // Build edges with offset-based cursors
  // opencti-ng has no inference system — default types to ['manual']
  // so that StixObjectOrStixRelationshipRefEdge.types is never null.
  const edges: BasicNodeEdge<T>[] = typedEntities.map((entity, i) => ({
    node: entity,
    cursor: offsetToCursor([offset + i]),
    types: ['manual'],
  }));

  return buildPaginationFromEdges<T>(first, after, edges, totalCount);
};

// ---------------------------------------------------------------------------
// Abstract types — these map to multiple concrete types and don't have
// a dedicated detail table.
// ---------------------------------------------------------------------------

const ABSTRACT_TYPES = new Set([
  'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object',
  'Stix-Cyber-Observable', 'Stix-Meta-Object',
  'Identity', 'Location', 'Container',
  'Basic-Object', 'Basic-Relationship',
  'stix-core-relationship', 'stix-sighting-relationship',
]);

const isAbstractType = (type: string): boolean => ABSTRACT_TYPES.has(type);

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
 * Uses POST /api/v1/stix/elements to batch-load all IDs in a single HTTP call.
 * When opts.type contains a single concrete (non-abstract) type, passes it
 * as `types` in the request body so the backend LEFT JOINs the detail table
 * and returns type-specific columns in `details`.
 *
 * Returns T[] by default, or Record<string, T> if toMap is true.
 */
export const elFindByIdsTiDB = async <T extends BasicStoreBase>(
  _context: AuthContext,
  _user: AuthUser,
  ids: string[] | string,
  opts: TiDBFindByIdsOpts = {},
): Promise<T[] | Record<string, T>> => {
  const { toMap = false, mapWithAllIds = false } = opts;

  const idsArray = Array.isArray(ids) ? ids : [ids];
  const processIds = idsArray.filter((id) => id != null && id !== '');
  if (processIds.length === 0) {
    return toMap ? {} as Record<string, T> : [] as T[];
  }

  const token = getApiToken();

  // Build request body — include types when a single concrete type is specified
  const typeHints = opts.type
    ? (Array.isArray(opts.type) ? opts.type : [opts.type])
    : [];
  const useDedicatedTypes = typeHints.length === 1 && !isAbstractType(typeHints[0]);

  const body: Record<string, any> = { ids: processIds };
  if (useDedicatedTypes) {
    body.types = typeHints;
  }

  // Single batch call with optional type hint for detail table JOIN
  const result = await apiPost<ApiListResponse>('stix/elements', body, token);

  const entities: T[] = result.data.map((e) => {
    const store = elementToStoreEntity(e);
    // Merge detail columns into the store entity at top level
    if (e.details && typeof e.details === 'object') {
      Object.assign(store, e.details);
    }
    return store as T;
  });

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
