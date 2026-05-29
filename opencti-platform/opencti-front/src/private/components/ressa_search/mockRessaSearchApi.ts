export type ExecutionMode = 'ElasticsearchDsl' | 'OpenCtiGraphql' | 'Unknown';

export interface RawQueryPrimaryTableColumn {
  name: string;
  type: string;
}

export type RawQueryPrimaryTableRow = Array<string | number | boolean | null>;

export interface RawQueryPrimaryTable {
  columns: RawQueryPrimaryTableColumn[];
  rows: RawQueryPrimaryTableRow[];
}

export interface RawQueryDocument<TSource = Record<string, unknown>> {
  index: string;
  id: string;
  internalId: string;
  standardId: string;
  entityType: string;
  source: TSource;
  depth: number;
  linkedFromInternalId: string | null;
}

export interface RawQueryRelationship {
  index: string;
  id: string;
  internalId: string;
  relationshipType: string;
  fromInternalId: string;
  toInternalId: string;
  source: Record<string, unknown>;
  depth: number;
}

export interface RawQueryStats {
  primaryRowCount: number;
  primaryDocumentCount: number;
  relatedEntityCount: number;
  relationshipCount: number;
  relatedDocumentCount: number;
  depthReached: number;
}

export interface RawQueryResponse {
  executionMode: ExecutionMode;
  esql?: string;
  elasticsearchDsl?: Record<string, unknown>;
  warnings?: string[];
  primary: RawQueryPrimaryTable;
  primaryDocuments: Array<RawQueryDocument>;
  relatedEntities: Array<unknown>;
  relationships: Array<RawQueryRelationship>;
  relatedDocuments: Array<RawQueryDocument>;
  stats: RawQueryStats;
}

export interface RawQueryRequest {
  query: string;
  maxRelationDepth?: number;
  maxPrimaryDocuments?: number;
  maxRelatedEntities?: number;
  maxRelationships?: number;
  maxRelatedDocuments?: number;
  includeRelationshipDocuments?: boolean;
  includeNestedObjects?: boolean;
  includeMetadataAndHistory?: boolean;
  multilineOutput?: boolean;
}

const sleep = async (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const isoNowMinusMinutes = (minutes: number) =>
  new Date(Date.now() - minutes * 60 * 1000).toISOString();

const buildObservedDataUrlLeakSample = (): RawQueryResponse => {
  const columns: RawQueryPrimaryTableColumn[] = [
    { name: '_index', type: 'keyword' },
    { name: '_id', type: 'keyword' },
    { name: 'internal_id', type: 'keyword' },
    { name: 'standard_id', type: 'keyword' },
    { name: 'entity_type', type: 'keyword' },
  ];

  const primaryDocuments: Array<RawQueryDocument> = [
    {
      index: 'opencti_stix_domain_objects-000001',
      id: 'd6836095-a418-4c9f-8b82-b5de23214963',
      internalId: 'd6836095-a418-4c9f-8b82-b5de23214963',
      standardId: 'observed-data--61d6c909-4fa5-5979-8e0f-30a8b96b1673',
      entityType: 'Observed-Data',
      source: {
        entity_type: 'Observed-Data',
        created_at: isoNowMinusMinutes(46),
        updated_at: isoNowMinusMinutes(42),
        confidence: 85,
        first_observed: isoNowMinusMinutes(60),
        last_observed: isoNowMinusMinutes(60),
        number_observed: 1,
        name: 'Credential leak telemetry',
        objects: [
          {
            type: 'url',
            value: 'https://portal.example.com/login',
            extensions: {
              login: true,
              password: true,
              cookie: true,
            },
          },
        ],
      },
      depth: 0,
      linkedFromInternalId: null,
    },
    {
      index: 'opencti_stix_domain_objects-000001',
      id: 'c97e989d-0f6f-4816-996a-65b318dc3bb7',
      internalId: 'c97e989d-0f6f-4816-996a-65b318dc3bb7',
      standardId: 'observed-data--d7a804a9-e33e-50f0-b7a7-f46c4fa2d036',
      entityType: 'Observed-Data',
      source: {
        entity_type: 'Observed-Data',
        created_at: isoNowMinusMinutes(95),
        updated_at: isoNowMinusMinutes(90),
        confidence: 100,
        first_observed: isoNowMinusMinutes(120),
        last_observed: isoNowMinusMinutes(120),
        number_observed: 1,
        name: 'Session replay artifacts',
        objects: [
          {
            type: 'url',
            value: 'https://billing.example.net/auth',
            extensions: {
              login: true,
              password: true,
              cookie: true,
            },
          },
        ],
      },
      depth: 0,
      linkedFromInternalId: null,
    },
  ];

  const rows: RawQueryPrimaryTableRow[] = primaryDocuments.map((d) => [
    d.index,
    d.id,
    d.internalId,
    d.standardId,
    d.entityType,
  ]);

  return {
    executionMode: 'ElasticsearchDsl',
    esql:
      'FROM opencti_stix_domain_objects* METADATA _index, _id\n' +
      'WHERE entity_type == "observed-data"\n' +
      'EVAL obj = objects\n' +
      'MV_EXPAND obj\n' +
      'EVAL obj_type = obj.type\n' +
      'WHERE obj_type == "url"\n' +
      'EVAL login = obj.extensions.login\n' +
      'EVAL password = obj.extensions.password\n' +
      'EVAL cookie = obj.extensions.cookie\n' +
      'WHERE login == true AND password == true AND cookie == true',
    warnings: [
      "spath path 'objects{}' uses Splunk array wildcards; nested OpenCTI objects may require MV_EXPAND or relationship expansion.",
      "OpenCTI mode maps SPL field 'type' to 'entity_type' and queries native OpenCTI indices.",
    ],
    primary: { columns, rows },
    primaryDocuments,
    relatedEntities: [],
    relationships: [],
    relatedDocuments: [],
    stats: {
      primaryRowCount: rows.length,
      primaryDocumentCount: primaryDocuments.length,
      relatedEntityCount: 0,
      relationshipCount: 0,
      relatedDocumentCount: 0,
      depthReached: 0,
    },
  };
};

const buildThreatReportSample = (): RawQueryResponse => {
  const primaryDocuments: Array<RawQueryDocument> = [
    {
      index: 'opencti_stix_domain_objects-000001',
      id: 'e12bca66-4b3a-4552-b3e4-2b9ae9f1c0e5',
      internalId: 'e12bca66-4b3a-4552-b3e4-2b9ae9f1c0e5',
      standardId: 'report--53d9dff8-ae2f-4c32-9ef2-6b6f18f8db9b',
      entityType: 'Report',
      source: {
        entity_type: 'Report',
        created_at: isoNowMinusMinutes(480),
        updated_at: isoNowMinusMinutes(300),
        confidence: 70,
        name: 'Banking sector threat brief',
        description: 'TLP:CLEAR synthetic sample for UI integration.',
        labels: ['Banking', 'Iran', 'High'],
      },
      depth: 0,
      linkedFromInternalId: null,
    },
    {
      index: 'opencti_stix_domain_objects-000001',
      id: 'd1ee34d6-6b33-4c0f-8b62-ec3a67edb01a',
      internalId: 'd1ee34d6-6b33-4c0f-8b62-ec3a67edb01a',
      standardId: 'report--b2f2de80-13bd-4bb5-b3f1-0e3c5e6c0fb1',
      entityType: 'Report',
      source: {
        entity_type: 'Report',
        created_at: isoNowMinusMinutes(1440),
        updated_at: isoNowMinusMinutes(1200),
        confidence: 55,
        name: 'Energy sector IOC roundup',
        description: 'TLP:AMBER synthetic sample for UI integration.',
        labels: ['Energy', 'IOC', 'Medium'],
      },
      depth: 0,
      linkedFromInternalId: null,
    },
  ];

  const columns: RawQueryPrimaryTableColumn[] = [
    { name: '_index', type: 'keyword' },
    { name: '_id', type: 'keyword' },
    { name: 'internal_id', type: 'keyword' },
    { name: 'standard_id', type: 'keyword' },
    { name: 'entity_type', type: 'keyword' },
  ];

  const rows: RawQueryPrimaryTableRow[] = primaryDocuments.map((d) => [
    d.index,
    d.id,
    d.internalId,
    d.standardId,
    d.entityType,
  ]);

  return {
    executionMode: 'ElasticsearchDsl',
    primary: { columns, rows },
    primaryDocuments,
    relatedEntities: [],
    relationships: [],
    relatedDocuments: [],
    stats: {
      primaryRowCount: rows.length,
      primaryDocumentCount: primaryDocuments.length,
      relatedEntityCount: 0,
      relationshipCount: 0,
      relatedDocumentCount: 0,
      depthReached: 0,
    },
  };
};

const buildEmptySample = (warning: string): RawQueryResponse => {
  const columns: RawQueryPrimaryTableColumn[] = [
    { name: '_index', type: 'keyword' },
    { name: '_id', type: 'keyword' },
    { name: 'internal_id', type: 'keyword' },
    { name: 'standard_id', type: 'keyword' },
    { name: 'entity_type', type: 'keyword' },
  ];
  return {
    executionMode: 'ElasticsearchDsl',
    warnings: [warning],
    primary: { columns, rows: [] },
    primaryDocuments: [],
    relatedEntities: [],
    relationships: [],
    relatedDocuments: [],
    stats: {
      primaryRowCount: 0,
      primaryDocumentCount: 0,
      relatedEntityCount: 0,
      relationshipCount: 0,
      relatedDocumentCount: 0,
      depthReached: 0,
    },
  };
};

const chooseMockResponse = (request: RawQueryRequest): RawQueryResponse => {
  const q = request.query.toLowerCase();

  if (
    q.includes('type="observed-data"') ||
    (q.includes('observed-data') && q.includes('obj_type="url"'))
  ) {
    return buildObservedDataUrlLeakSample();
  }

  if (q.includes('country: "iran"') || q.includes('country:"iran"')) {
    return buildThreatReportSample();
  }

  if (q.includes('alpha strike lab') && q.includes('cve-2025-27865')) {
    return buildEmptySample('No documents matched the requested criteria.');
  }

  if (q.includes('error(') || q.includes('syntax')) {
    throw new Error('Mock parse error: invalid query syntax');
  }

  return buildThreatReportSample();
};

export async function mockRawQueryApi(request: RawQueryRequest): Promise<RawQueryResponse> {
  await sleep(650);
  return chooseMockResponse(request);
}

