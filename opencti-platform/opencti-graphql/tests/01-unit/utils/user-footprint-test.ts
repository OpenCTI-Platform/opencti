import { describe, expect, it } from 'vitest';
import {
  buildUserFootprintScopes,
  buildUserFootprintSearch,
  parseUserFootprintSearch,
  summarizeUserFootprint,
  USER_FOOTPRINT_COVERAGE,
  type UserFootprintScope,
} from '../../../src/utils/user-footprint';

const USER_ID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';

const buildScopes = () => buildUserFootprintScopes({
  userId: USER_ID,
  schemaFieldNames: ['user_id', 'creator_id', 'creator_id'],
  indices: {
    active: ['opencti_internal_objects*', 'opencti_internal_relationships*'],
    draft: 'opencti_draft_objects*',
    history: 'opencti_history*',
    files: 'opencti_files*',
    deleted: 'opencti_deleted_objects*',
  },
  relationDatabaseNames: {
    assignee: 'object-assignee',
    participant: 'object-participant',
  },
});

describe('User footprint registry', () => {
  it('uses physical relationship fields and covers dedicated indices', () => {
    const scopes = buildScopes();
    expect(scopes.map(({ id }) => id)).toEqual(['active', 'draft', 'history', 'files', 'deleted']);
    expect(scopes.find(({ id }) => id === 'active')?.references).toEqual(expect.arrayContaining([
      expect.objectContaining({
        label: 'rel_object-assignee.internal_id',
        query: { term: { 'rel_object-assignee.internal_id.keyword': { value: USER_ID } } },
      }),
      expect.objectContaining({
        label: 'rel_object-participant.internal_id',
        query: { term: { 'rel_object-participant.internal_id.keyword': { value: USER_ID } } },
      }),
    ]));
    expect(scopes.find(({ id }) => id === 'history')?.indices).toEqual(['opencti_history*']);
    expect(scopes.find(({ id }) => id === 'files')?.indices).toEqual(['opencti_files*']);
    expect(scopes.find(({ id }) => id === 'deleted')?.indices).toEqual(['opencti_deleted_objects*']);
    expect(scopes.find(({ id }) => id === 'draft')?.indices).toEqual(['opencti_draft_objects*']);
  });

  it('registers exact nested fields and candidate serialized fields separately', () => {
    const active = buildScopes().find(({ id }) => id === 'active');
    expect(active?.references).toEqual(expect.arrayContaining([
      expect.objectContaining({
        label: 'restricted_members[].id',
        certainty: 'exact',
        query: {
          nested: {
            path: 'restricted_members',
            query: { term: { 'restricted_members.id.keyword': { value: USER_ID } } },
            ignore_unmapped: true,
          },
        },
      }),
      expect.objectContaining({
        label: 'pendingTransition JSON',
        certainty: 'candidate',
        disposition: 'conditional',
      }),
      expect.objectContaining({
        label: 'i_attributes.user_id',
        disposition: 'retain',
      }),
    ]));
  });

  it('classifies direct source memberships for invalidation and anomalous rights for review', () => {
    const active = buildScopes().find(({ id }) => id === 'active');
    expect(active?.references).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: 'active.rights.member-of.from',
        category: 'source_membership',
        disposition: 'invalidate',
      }),
      expect.objectContaining({
        id: 'active.rights.has-role.from',
        category: 'unexpected_direct_right',
        disposition: 'conditional',
      }),
    ]));
  });
});

describe('User footprint queries and result parsing', () => {
  const scope: UserFootprintScope = {
    id: 'active',
    label: 'Active data',
    indices: ['opencti_internal_objects*'],
    references: [
      {
        id: 'active.creator',
        label: 'creator_id',
        category: 'schema_root_field',
        disposition: 'transfer',
        certainty: 'exact',
        query: { term: { 'creator_id.keyword': { value: USER_ID } } },
      },
      {
        id: 'active.user',
        label: 'user_id',
        category: 'schema_root_field',
        disposition: 'conditional',
        certainty: 'exact',
        query: { term: { 'user_id.keyword': { value: USER_ID } } },
      },
    ],
  };

  it('builds one OR query with unique counts per reference and disposition', () => {
    const search = buildUserFootprintSearch(scope);
    expect(search.body.track_total_hits).toBe(true);
    expect(search.body.query.bool.should).toHaveLength(2);
    expect(search.body.aggs.references.filters.filters).toHaveProperty('active.creator');
    expect(search.body.aggs.dispositions.filters.filters).toHaveProperty('transfer');
    expect(search.body.aggs.dispositions.filters.filters).toHaveProperty('conditional');
    expect(search.body.aggs.certainties.filters.filters).toHaveProperty('exact');
  });

  it('keeps the scope total deduplicated while exposing overlapping reference counts', () => {
    const result = parseUserFootprintSearch(scope, {
      hits: { total: { value: 3, relation: 'eq' }, hits: [] },
      aggregations: {
        references: {
          buckets: {
            'active.creator': { doc_count: 3 },
            'active.user': { doc_count: 2 },
          },
        },
        dispositions: {
          buckets: {
            transfer: { doc_count: 3 },
            conditional: { doc_count: 2 },
          },
        },
        certainties: {
          buckets: {
            exact: { doc_count: 3 },
          },
        },
      },
    });
    expect(result.uniqueDocuments).toBe(3);
    expect(result.references['active.creator'].count).toBe(3);
    expect(result.references['active.user'].count).toBe(2);

    const summary = summarizeUserFootprint({ active: result });
    expect(summary.uniquePersistentDocuments).toBe(3);
    expect(summary.exactUniquePersistentDocuments).toBe(3);
    expect(summary.candidateUniquePersistentDocuments).toBe(0);
    expect(summary.referenceMatches).toBe(5);
    expect(summary.dispositions).toEqual({ transfer: 3, conditional: 2 });
  });

  it('rejects incomplete Elasticsearch responses instead of returning success-shaped defaults', () => {
    expect(() => parseUserFootprintSearch(scope, { hits: { total: 0 } })).toThrow(
      'Invalid Elasticsearch footprint response at aggregations.references.buckets',
    );
  });
});

describe('User footprint coverage reporting', () => {
  it('explicitly reports storage that is not scanned', () => {
    expect(USER_FOOTPRINT_COVERAGE.unsupported.map(({ storage }) => storage)).toEqual([
      'Redis',
      'RabbitMQ',
      'Object storage',
    ]);
    expect(USER_FOOTPRINT_COVERAGE.unknowns).not.toHaveLength(0);
  });
});
