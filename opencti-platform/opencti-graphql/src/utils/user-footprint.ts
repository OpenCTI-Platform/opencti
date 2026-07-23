import {
  RELATION_ACCESSES_TO,
  RELATION_HAS_CAPABILITY,
  RELATION_HAS_CAPABILITY_IN_DRAFT,
  RELATION_HAS_ROLE,
  RELATION_MEMBER_OF,
  RELATION_PARTICIPATE_TO,
} from '../schema/internalRelationship';
import { ENTITY_TYPE_WORKFLOW_DEFINITION, ENTITY_TYPE_WORKFLOW_INSTANCE } from '../modules/workflow/types/workflow-types';

export type UserFootprintDisposition = 'transfer' | 'retain' | 'invalidate' | 'conditional';
export type UserFootprintCertainty = 'exact' | 'candidate';

type QueryClause = Record<string, unknown>;

export interface UserFootprintReference {
  id: string;
  label: string;
  category: string;
  disposition: UserFootprintDisposition;
  certainty: UserFootprintCertainty;
  query: QueryClause;
}

export interface UserFootprintScope {
  id: 'active' | 'draft' | 'history' | 'files' | 'deleted';
  label: string;
  indices: string[];
  references: UserFootprintReference[];
}

export interface UserFootprintScopeResult {
  label: string;
  indices: string[];
  uniqueDocuments: number;
  certainties: Partial<Record<UserFootprintCertainty, number>>;
  references: Record<string, Omit<UserFootprintReference, 'id' | 'query'> & { count: number }>;
  dispositions: Partial<Record<UserFootprintDisposition, number>>;
}

export interface UserFootprintSummary {
  uniquePersistentDocuments: number;
  exactUniquePersistentDocuments: number;
  candidateUniquePersistentDocuments: number;
  referenceMatches: number;
  dispositions: Partial<Record<UserFootprintDisposition, number>>;
  countingSemantics: {
    scopeCounts: string;
    certaintyCounts: string;
    dispositionCounts: string;
    referenceCounts: string;
  };
}

export interface BuildUserFootprintScopesArgs {
  userId: string;
  schemaFieldNames: string[];
  indices: {
    active: string[];
    draft: string;
    history: string;
    files: string;
    deleted: string;
  };
  relationDatabaseNames: {
    assignee: string;
    participant: string;
  };
}

const ROOT_FIELD_DISPOSITIONS: Record<string, UserFootprintDisposition> = {
  creator_id: 'transfer',
  platform_ip_whitelist_exclusion_ids: 'invalidate',
  xtm_hub_registration_user_id: 'transfer',
  user_id: 'conditional',
  applicant_id: 'conditional',
  recipients: 'transfer',
  feed_public_user_id: 'conditional',
  taxii_public_user_id: 'conditional',
  stream_public_user_id: 'conditional',
};

const exact = (field: string, value: string): QueryClause => ({
  term: { [`${field}.keyword`]: { value } },
});

const phrase = (field: string, value: string): QueryClause => ({
  match_phrase: { [field]: value },
});

const nested = (path: string, query: QueryClause): QueryClause => ({
  nested: { path, query, ignore_unmapped: true },
});

const typed = (entityType: string, query: QueryClause): QueryClause => ({
  bool: {
    must: [
      exact('entity_type', entityType),
      query,
    ],
  },
});

const nestedExact = (path: string, field: string, value: string): QueryClause => nested(path, exact(field, value));
const nestedPhrase = (path: string, field: string, value: string): QueryClause => nested(path, phrase(field, value));

const createReference = (
  id: string,
  label: string,
  category: string,
  disposition: UserFootprintDisposition,
  certainty: UserFootprintCertainty,
  query: QueryClause,
): UserFootprintReference => ({ id, label, category, disposition, certainty, query });

const buildSchemaReferences = (
  prefix: string,
  userId: string,
  schemaFieldNames: string[],
  historical: boolean,
): UserFootprintReference[] => {
  return [...new Set(schemaFieldNames)].sort().map((field) => createReference(
    `${prefix}.schema.${field}`,
    field,
    'schema_root_field',
    historical ? 'retain' : (ROOT_FIELD_DISPOSITIONS[field] ?? 'conditional'),
    'exact',
    exact(field, userId),
  ));
};

const buildCommonObjectReferences = (
  prefix: string,
  userId: string,
  historical: boolean,
  relationDatabaseNames: BuildUserFootprintScopesArgs['relationDatabaseNames'],
): UserFootprintReference[] => {
  const operationalDisposition = historical ? 'retain' : 'transfer';
  const lifecycleDisposition = historical ? 'retain' : 'conditional';
  const securityDisposition = historical ? 'retain' : 'invalidate';
  return [
    createReference(`${prefix}.nested.i_attributes.user_id`, 'i_attributes.user_id', 'attribute_history', 'retain', 'exact', exact('i_attributes.user_id', userId)),
    createReference(`${prefix}.nested.restricted_members.id`, 'restricted_members[].id', 'restricted_members', operationalDisposition, 'exact', nestedExact('restricted_members', 'restricted_members.id', userId)),
    createReference(
      `${prefix}.nested.connections.internal_id`,
      'connections[].internal_id',
      'generic_graph_reference',
      historical ? 'retain' : 'conditional',
      'exact',
      nestedExact('connections', 'connections.internal_id', userId),
    ),
    createReference(`${prefix}.field.connector_user_id`, 'connector_user_id', 'operational_reference', lifecycleDisposition, 'exact', exact('connector_user_id', userId)),
    createReference(`${prefix}.field.initiator_id`, 'initiator_id', 'lifecycle_reference', lifecycleDisposition, 'exact', exact('initiator_id', userId)),
    createReference(`${prefix}.field.authorized_authorities`, 'authorized_authorities[]', 'security_right', securityDisposition, 'exact', exact('authorized_authorities', userId)),
    createReference(`${prefix}.field.activity_listeners_ids`, 'activity_listeners_ids[]', 'security_subscription', securityDisposition, 'exact', exact('activity_listeners_ids', userId)),
    createReference(
      `${prefix}.ref.object-assignee`,
      `rel_${relationDatabaseNames.assignee}.internal_id`,
      'stix_reference',
      operationalDisposition,
      'exact',
      exact(`rel_${relationDatabaseNames.assignee}.internal_id`, userId),
    ),
    createReference(
      `${prefix}.ref.object-participant`,
      `rel_${relationDatabaseNames.participant}.internal_id`,
      'stix_reference',
      operationalDisposition,
      'exact',
      exact(`rel_${relationDatabaseNames.participant}.internal_id`, userId),
    ),
    createReference(
      `${prefix}.workflow.published.createdBy`,
      'published_version.createdBy',
      'historical_provenance',
      'retain',
      'exact',
      typed(ENTITY_TYPE_WORKFLOW_DEFINITION, nestedExact('published_version', 'published_version.createdBy', userId)),
    ),
    createReference(
      `${prefix}.workflow.draft.createdBy`,
      'draft_version.createdBy',
      'historical_provenance',
      'retain',
      'exact',
      typed(ENTITY_TYPE_WORKFLOW_DEFINITION, nestedExact('draft_version', 'draft_version.createdBy', userId)),
    ),
    createReference(
      `${prefix}.workflow.all.createdBy`,
      'all_versions[].createdBy',
      'historical_provenance',
      'retain',
      'exact',
      typed(ENTITY_TYPE_WORKFLOW_DEFINITION, nestedExact('all_versions', 'all_versions.createdBy', userId)),
    ),
    createReference(
      `${prefix}.workflow.history`,
      'history JSON',
      'historical_provenance',
      'retain',
      'candidate',
      typed(ENTITY_TYPE_WORKFLOW_INSTANCE, phrase('history', userId)),
    ),
    createReference(
      `${prefix}.workflow.pendingTransition`,
      'pendingTransition JSON',
      'lifecycle_reference',
      lifecycleDisposition,
      'candidate',
      typed(ENTITY_TYPE_WORKFLOW_INSTANCE, phrase('pendingTransition', userId)),
    ),
    ...['published_version', 'draft_version', 'all_versions'].map((path) => createReference(
      `${prefix}.workflow.${path}.content`,
      `${path}.content JSON`,
      'serialized_configuration',
      operationalDisposition,
      'candidate',
      typed(ENTITY_TYPE_WORKFLOW_DEFINITION, nestedPhrase(path, `${path}.content`, userId)),
    )),
    ...[
      'filters',
      'origin_filters',
      'connector_trigger_filters',
      'task_filters',
      'pir_filters',
      'decay_filters',
      'decay_exclusion_filters',
      'instance_filters',
      'list_filters',
      'metaData.list_filters',
      'manifest',
    ].map((field) => createReference(
      `${prefix}.serialized.${field}`,
      `${field} serialized content`,
      'serialized_configuration',
      operationalDisposition,
      'candidate',
      phrase(field, userId),
    )),
  ];
};

const relationshipSideQuery = (relationshipType: string, side: 'from' | 'to', userId: string): QueryClause => typed(
  relationshipType,
  nested('connections', {
    bool: {
      must: [
        exact('connections.internal_id', userId),
        exact('connections.role', `${relationshipType}_${side}`),
      ],
    },
  }),
);

const buildRightsReferences = (userId: string): UserFootprintReference[] => {
  const relationshipTypes = [
    RELATION_MEMBER_OF,
    RELATION_PARTICIPATE_TO,
    RELATION_HAS_ROLE,
    RELATION_HAS_CAPABILITY,
    RELATION_HAS_CAPABILITY_IN_DRAFT,
    RELATION_ACCESSES_TO,
  ];
  return relationshipTypes.flatMap((relationshipType) => {
    const expectedDirectMembership = relationshipType === RELATION_MEMBER_OF || relationshipType === RELATION_PARTICIPATE_TO;
    return (['from', 'to'] as const).map((side) => createReference(
      `active.rights.${relationshipType}.${side}`,
      `${relationshipType} (${side} side)`,
      expectedDirectMembership && side === 'from' ? 'source_membership' : 'unexpected_direct_right',
      expectedDirectMembership && side === 'from' ? 'invalidate' : 'conditional',
      'exact',
      relationshipSideQuery(relationshipType, side, userId),
    ));
  });
};

export const buildUserFootprintScopes = ({
  userId,
  schemaFieldNames,
  indices,
  relationDatabaseNames,
}: BuildUserFootprintScopesArgs): UserFootprintScope[] => {
  const activeReferences = [
    ...buildSchemaReferences('active', userId, schemaFieldNames, false),
    ...buildCommonObjectReferences('active', userId, false, relationDatabaseNames),
    ...buildRightsReferences(userId),
  ];
  const draftReferences = [
    ...buildSchemaReferences('draft', userId, schemaFieldNames, false),
    ...buildCommonObjectReferences('draft', userId, false, relationDatabaseNames),
  ];
  const deletedReferences = [
    ...buildSchemaReferences('deleted', userId, schemaFieldNames, true),
    ...buildCommonObjectReferences('deleted', userId, true, relationDatabaseNames),
  ];

  return [
    { id: 'active', label: 'Active platform data', indices: indices.active, references: activeReferences },
    { id: 'draft', label: 'Draft object copies', indices: [indices.draft], references: draftReferences },
    {
      id: 'history',
      label: 'Audit and activity history',
      indices: [indices.history],
      references: [
        createReference('history.user_id', 'user_id', 'historical_provenance', 'retain', 'exact', exact('user_id', userId)),
        createReference('history.applicant_id', 'applicant_id', 'historical_provenance', 'retain', 'exact', exact('applicant_id', userId)),
        createReference('history.context.creator_ids', 'context_data.creator_ids', 'historical_provenance', 'retain', 'exact', exact('context_data.creator_ids', userId)),
        createReference(
          'history.restricted_members.id',
          'restricted_members[].id',
          'historical_access',
          'retain',
          'exact',
          nestedExact('restricted_members', 'restricted_members.id', userId),
        ),
      ],
    },
    {
      id: 'files',
      label: 'Indexed file metadata',
      indices: [indices.files],
      references: [
        createReference('files.metaData.creator_id', 'metaData.creator_id', 'historical_provenance', 'retain', 'exact', exact('metaData.creator_id', userId)),
      ],
    },
    { id: 'deleted', label: 'Deleted object copies', indices: [indices.deleted], references: deletedReferences },
  ];
};

const groupQueries = <T extends string>(references: UserFootprintReference[], selector: (reference: UserFootprintReference) => T): Record<string, QueryClause> => {
  const grouped = new Map<T, QueryClause[]>();
  for (const reference of references) {
    const group = selector(reference);
    const queries = grouped.get(group) ?? [];
    queries.push(reference.query);
    grouped.set(group, queries);
  }
  return Object.fromEntries([...grouped.entries()].map(([group, queries]) => [
    group,
    { bool: { should: queries, minimum_should_match: 1 } },
  ]));
};

export const buildUserFootprintSearch = (scope: UserFootprintScope) => {
  const referenceFilters = Object.fromEntries(scope.references.map((reference) => [reference.id, reference.query]));
  const dispositionFilters = groupQueries(scope.references, (reference) => reference.disposition);
  const certaintyFilters = groupQueries(scope.references, (reference) => reference.certainty);
  return {
    index: scope.indices,
    allow_no_indices: true,
    ignore_unavailable: true,
    body: {
      size: 0,
      track_total_hits: true,
      query: {
        bool: {
          should: scope.references.map((reference) => reference.query),
          minimum_should_match: 1,
        },
      },
      aggs: {
        references: { filters: { filters: referenceFilters } },
        dispositions: { filters: { filters: dispositionFilters } },
        certainties: { filters: { filters: certaintyFilters } },
      },
    },
  };
};

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

const readCount = (value: unknown, path: string): number => {
  if (!isRecord(value) || typeof value.doc_count !== 'number') {
    throw new Error(`Invalid Elasticsearch footprint response at ${path}`);
  }
  return value.doc_count;
};

const readBuckets = (response: Record<string, unknown>, aggregation: string): Record<string, unknown> => {
  const aggregations = response.aggregations;
  if (!isRecord(aggregations) || !isRecord(aggregations[aggregation]) || !isRecord(aggregations[aggregation].buckets)) {
    throw new Error(`Invalid Elasticsearch footprint response at aggregations.${aggregation}.buckets`);
  }
  return aggregations[aggregation].buckets;
};

const readTotalHits = (response: Record<string, unknown>): number => {
  const hits = response.hits;
  if (!isRecord(hits)) {
    throw new Error('Invalid Elasticsearch footprint response at hits');
  }
  if (typeof hits.total === 'number') {
    return hits.total;
  }
  if (isRecord(hits.total) && typeof hits.total.value === 'number') {
    return hits.total.value;
  }
  throw new Error('Invalid Elasticsearch footprint response at hits.total');
};

export const parseUserFootprintSearch = (scope: UserFootprintScope, rawResponse: unknown): UserFootprintScopeResult => {
  if (!isRecord(rawResponse)) {
    throw new Error('Invalid Elasticsearch footprint response');
  }
  const referenceBuckets = readBuckets(rawResponse, 'references');
  const dispositionBuckets = readBuckets(rawResponse, 'dispositions');
  const certaintyBuckets = readBuckets(rawResponse, 'certainties');
  const references = Object.fromEntries(scope.references.map(({ id, query: _, ...reference }) => {
    const bucket = referenceBuckets[id];
    return [id, { ...reference, count: readCount(bucket, `aggregations.references.buckets.${id}`) }];
  }));
  const dispositions = Object.fromEntries(Object.entries(dispositionBuckets).map(([disposition, bucket]) => [
    disposition,
    readCount(bucket, `aggregations.dispositions.buckets.${disposition}`),
  ]));
  const certainties = Object.fromEntries(Object.entries(certaintyBuckets).map(([certainty, bucket]) => [
    certainty,
    readCount(bucket, `aggregations.certainties.buckets.${certainty}`),
  ]));

  return {
    label: scope.label,
    indices: scope.indices,
    uniqueDocuments: readTotalHits(rawResponse),
    references,
    dispositions,
    certainties,
  };
};

export const summarizeUserFootprint = (scopeResults: Record<string, UserFootprintScopeResult>): UserFootprintSummary => {
  const dispositions: Partial<Record<UserFootprintDisposition, number>> = {};
  let uniquePersistentDocuments = 0;
  let exactUniquePersistentDocuments = 0;
  let candidateUniquePersistentDocuments = 0;
  let referenceMatches = 0;
  for (const scope of Object.values(scopeResults)) {
    uniquePersistentDocuments += scope.uniqueDocuments;
    exactUniquePersistentDocuments += scope.certainties.exact ?? 0;
    candidateUniquePersistentDocuments += scope.certainties.candidate ?? 0;
    referenceMatches += Object.values(scope.references).reduce((total, reference) => total + reference.count, 0);
    for (const [disposition, count] of Object.entries(scope.dispositions)) {
      const typedDisposition = disposition as UserFootprintDisposition;
      dispositions[typedDisposition] = (dispositions[typedDisposition] ?? 0) + count;
    }
  }
  return {
    uniquePersistentDocuments,
    exactUniquePersistentDocuments,
    candidateUniquePersistentDocuments,
    referenceMatches,
    dispositions,
    countingSemantics: {
      scopeCounts: 'Unique physical Elasticsearch documents matched within each disjoint index scope.',
      certaintyCounts: 'Unique within each certainty and scope; exact and candidate counts can overlap.',
      dispositionCounts: 'Unique within each disposition and scope; a document matching different dispositions appears in each relevant disposition.',
      referenceCounts: 'Per-reference matches are diagnostic and must not be summed as a unique object count.',
    },
  };
};

export const USER_FOOTPRINT_COVERAGE = {
  status: 'explicit_registry',
  handled: [
    'Schema-declared root user ID attributes',
    'Known nested and non-ID-typed user references',
    'Physical assignee and participant fields',
    'Known serialized filter and workflow fields (candidate matches)',
    'Active, draft, history, file metadata, and deleted-object Elasticsearch indices',
    'Direct rights and membership relationship anomalies',
  ],
  unsupported: [
    {
      storage: 'Redis',
      elements: ['sessions', 'API token cache and usage counters', 'OTP state', 'live stream state', 'locks'],
      expectedAction: 'Inspect separately; revoke/invalidate credentials and coordinate runtime state.',
    },
    {
      storage: 'RabbitMQ',
      elements: ['in-flight and persisted messages'],
      expectedAction: 'Pause or drain processing before merge.',
    },
    {
      storage: 'Object storage',
      elements: ['user IDs embedded in MinIO/S3 file contents'],
      expectedAction: 'Not scanned; indexed file metadata is covered separately.',
    },
  ],
  unknowns: [
    'Serialized user references in fields not registered above cannot be discovered reliably from mappings.',
    'Candidate JSON/text matches must be parsed structurally before any write.',
    'New non-schema storage forms require an explicit registry entry and a regression test.',
  ],
} as const;
