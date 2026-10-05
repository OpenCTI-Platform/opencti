import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  buildSourceResolver,
  isProvenanceAttributeAvailable,
  resolveDocumentAssertions,
  resolveEventSources,
  resolveProvenanceMode,
  userSource,
} from '../../../../src/modules/sourceIntelligence/sourceIntelligence-provenance';
import type { BasicStoreEntitySource } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

const source = (internal_id: string, source_kind: BasicStoreEntitySource['source_kind'], ref_id: string, source_user_ids: string[] = []) => ({
  internal_id,
  id: internal_id,
  name: internal_id,
  source_kind,
  ref_id,
  source_user_ids,
  enabled: true,
} as unknown as BasicStoreEntitySource);

const sources = [
  source('src-connector', 'connector', 'connector-1', ['user-connector']),
  source('src-feed', 'ingestion_feed', 'feed-1', ['user-feed']),
  source('src-author', 'author', 'identity-1'),
  source('src-analyst', 'manual', 'user-analyst', ['user-analyst']),
];

describe('Source intelligence provenance', () => {
  it('should consume the provenance attribute of innovation 06', () => {
    expect(isProvenanceAttributeAvailable()).toBe(true);
    expect(resolveProvenanceMode()).toEqual('assertions');
  });

  it('should fall back on the creators when provenance is switched off, as its assertions are no longer refreshed', () => {
    expect(isProvenanceAttributeAvailable(false)).toBe(false);
    expect(resolveProvenanceMode(false)).toEqual('creators');
  });

  it('should resolve the assertions of a document, one entry per source', () => {
    const resolver = buildSourceResolver(sources);
    const assertions = resolveDocumentAssertions({
      internal_id: 'malware-1',
      created_at: '2026-10-01T00:00:00.000Z',
      updated_at: '2026-10-02T00:00:00.000Z',
      x_opencti_assertions: [
        { source_id: 'connector-1', source_kind: 'connector', first_asserted_at: '2026-10-01T00:00:00.000Z', last_asserted_at: '2026-10-02T00:00:00.000Z' },
        { source_id: 'feed-1', source_kind: 'feed', first_asserted_at: '2026-10-01T06:00:00.000Z', last_asserted_at: null },
        { source_id: 'user-analyst', source_kind: 'user', first_asserted_at: '2026-10-01T08:00:00.000Z', last_asserted_at: '2026-10-01T08:00:00.000Z' },
        // Inference and emulation assertions are not intelligence sources
        { source_id: 'rule-1', source_kind: 'inference', first_asserted_at: '2026-10-01T00:00:00.000Z' },
        { source_id: 'unknown-connector', source_kind: 'connector', first_asserted_at: '2026-10-01T00:00:00.000Z' },
      ],
    }, resolver);
    const byId = new Map(assertions.map((a) => [a.sourceId, a]));
    expect(assertions).toHaveLength(3);
    expect(byId.get('src-connector')?.firstAt).toEqual(Date.parse('2026-10-01T00:00:00.000Z'));
    expect(byId.get('src-connector')?.lastAt).toEqual(Date.parse('2026-10-02T00:00:00.000Z'));
    // Without a last assertion date, the first one is used
    expect(byId.get('src-feed')?.lastAt).toEqual(Date.parse('2026-10-01T06:00:00.000Z'));
    expect(byId.has('src-analyst')).toBe(true);
  });

  it('should always resolve the author, even when the assertions do not carry it', () => {
    const resolver = buildSourceResolver(sources);
    const assertions = resolveDocumentAssertions({
      internal_id: 'report-1',
      created_at: '2026-10-01T00:00:00.000Z',
      'rel_created-by.internal_id': ['identity-1'],
      x_opencti_assertions: [{ source_id: 'connector-1', source_kind: 'connector', first_asserted_at: '2026-10-01T00:00:00.000Z' }],
    }, resolver);
    expect(assertions.map((a) => a.sourceId).sort()).toEqual(['src-author', 'src-connector']);
  });

  it('should fall back on the creators when a document carries no assertion', () => {
    const resolver = buildSourceResolver(sources);
    const assertions = resolveDocumentAssertions({
      internal_id: 'indicator-1',
      created_at: '2026-10-01T00:00:00.000Z',
      updated_at: '2026-10-03T00:00:00.000Z',
      creator_id: ['user-connector', 'user-feed'],
    }, resolver);
    const byId = new Map(assertions.map((a) => [a.sourceId, a]));
    // The first creator is dated at creation, the next ones have no first date (lead time not computable)
    expect(byId.get('src-connector')?.firstAt).toEqual(Date.parse('2026-10-01T00:00:00.000Z'));
    expect(byId.get('src-feed')?.firstAt).toBeNull();
    expect(byId.get('src-feed')?.lastAt).toEqual(Date.parse('2026-10-03T00:00:00.000Z'));
  });

  it('should resolve the sources of a stream event from its origin, creators and author', () => {
    const resolver = buildSourceResolver(sources);
    expect(resolveEventSources(resolver, { originUserId: 'user-feed', creatorIds: ['user-connector'], createdByRefId: 'identity-1' }).sort())
      .toEqual(['src-author', 'src-connector', 'src-feed']);
    expect(resolveEventSources(resolver, { originUserId: 'unknown-user' })).toEqual([]);
    expect(resolveEventSources(resolver, { assertions: [{ source_id: 'feed-1', source_kind: 'feed' }] })).toEqual(['src-feed']);
  });

  it('should credit no source for a user shared by several connectors', () => {
    const shared = [
      source('src-connector-a', 'connector', 'connector-a', ['user-shared']),
      source('src-connector-b', 'connector', 'connector-b', ['user-shared']),
      source('src-author', 'author', 'identity-1'),
    ];
    const resolver = buildSourceResolver(shared);
    expect(userSource(resolver, 'user-shared')).toBeUndefined();
    const assertions = resolveDocumentAssertions({
      internal_id: 'indicator-2',
      created_at: '2026-10-01T00:00:00.000Z',
      creator_id: ['user-shared'],
      'rel_created-by.internal_id': ['identity-1'],
    }, resolver);
    // The author is still known; the writing connector is not, so neither is credited nor corroborates the other
    expect(assertions.map((a) => a.sourceId)).toEqual(['src-author']);
    expect(resolveEventSources(resolver, { originUserId: 'user-shared', createdByRefId: 'identity-1' })).toEqual(['src-author']);
    expect(userSource(buildSourceResolver(sources), 'user-connector')).toEqual('src-connector');
  });

  it('should map aliases of referenced elements', () => {
    const resolver = buildSourceResolver(sources, [{ kind: 'connector', refId: 'feed-twin-connector', sourceId: 'src-feed' }]);
    const assertions = resolveDocumentAssertions({
      internal_id: 'malware-2',
      x_opencti_assertions: [{ source_id: 'feed-twin-connector', source_kind: 'connector', first_asserted_at: '2026-10-01T00:00:00.000Z' }],
    }, resolver);
    expect(assertions.map((a) => a.sourceId)).toEqual(['src-feed']);
  });
});
