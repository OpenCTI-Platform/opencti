import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntitySource } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import { SOURCE_KIND_AUTHOR, SOURCE_KIND_CONNECTOR } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

const { cachedSources, accessibleIdentities } = vi.hoisted(() => ({
  cachedSources: new Map<string, unknown>(),
  accessibleIdentities: new Set<string>(),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: vi.fn(async () => cachedSources),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => ids
    .filter((id) => accessibleIdentities.has(id))
    .map((id) => ({ internal_id: id }))),
}));

const { maskRestrictedNames, recordNamedAuthors, restrictedRecommendationNames, sourceAuditName } = await import('../../../../src/modules/sourceIntelligence/sourceIntelligence-domain');

const user = { id: 'analyst' } as AuthUser;
const authorSource = (id: string, refId: string, name: string) => ({ internal_id: id, source_kind: SOURCE_KIND_AUTHOR, ref_id: refId, name }) as BasicStoreEntitySource;
const recorded = (...authors: Array<[string, string]>) => JSON.stringify(authors.map(([ref_id, name]) => ({ ref_id, name })));
// Each request has its own context: the resolution is shared by the fields of one request only
const newContext = () => ({}) as AuthContext;

describe('Source intelligence recommendation masking', () => {
  beforeEach(() => {
    cachedSources.clear();
    accessibleIdentities.clear();
  });

  it('should mask the name a recommendation was written with after the author was renamed', async () => {
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme Threat Research'));
    const recommendation = { internal_id: 'rec-1', source_id: 'source-1', payload: '{}', named_authors: recorded(['identity-1', 'Acme']) };
    const names = await restrictedRecommendationNames(newContext(), user, recommendation);
    expect(names.sort()).toEqual(['Acme', 'Acme Threat Research']);
    expect(maskRestrictedNames('Raise the confidence of Acme (now Acme Threat Research)', names))
      .toBe('Raise the confidence of Restricted (now Restricted)');
  });

  it('should keep masking the recorded names once the source is no longer tracked', async () => {
    const recommendation = { internal_id: 'rec-1', source_id: 'source-1', payload: '{"peer_source_id":"source-2"}', named_authors: recorded(['identity-1', 'Acme'], ['identity-2', 'Globex']) };
    expect((await restrictedRecommendationNames(newContext(), user, recommendation)).sort()).toEqual(['Acme', 'Globex']);
  });

  it('should leave the names of accessible authors and of other source kinds visible', async () => {
    accessibleIdentities.add('identity-1');
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme'));
    cachedSources.set('source-2', { internal_id: 'source-2', source_kind: SOURCE_KIND_CONNECTOR, ref_id: 'connector-1', name: 'MISP' });
    const recommendation = { internal_id: 'rec-1', source_id: 'source-1', payload: '{"peer_source_id":"source-2"}', named_authors: recorded(['identity-1', 'Acme']) };
    expect(await restrictedRecommendationNames(newContext(), user, recommendation)).toEqual([]);
  });

  it('should mask the current name of a recommendation that recorded no author', async () => {
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme'));
    expect(await restrictedRecommendationNames(newContext(), user, { internal_id: 'rec-1', source_id: 'source-1', payload: '{}' })).toEqual(['Acme']);
  });

  it('should record the current names next to the recorded ones, the given sources first', async () => {
    cachedSources.set('source-1', authorSource('source-1', 'identity-1', 'Acme (cached)'));
    cachedSources.set('source-2', authorSource('source-2', 'identity-2', 'Globex'));
    const stored = await recordNamedAuthors(
      newContext(),
      { source_id: 'source-1', payload: '{"peer_source_id":"source-2"}', named_authors: recorded(['identity-1', 'Acme']) },
      [authorSource('source-1', 'identity-1', 'Acme Threat Research')],
    );
    expect(JSON.parse(stored)).toEqual([
      { ref_id: 'identity-1', name: 'Acme' },
      { ref_id: 'identity-1', name: 'Acme Threat Research' },
      { ref_id: 'identity-2', name: 'Globex' },
    ]);
  });

  it('should record nothing for a recommendation without author source', async () => {
    expect(await recordNamedAuthors(newContext(), { source_id: null, payload: '{"collection_gap_id":"gap-1"}' })).toBe('[]');
  });
});

describe('Source intelligence activity records', () => {
  it('should name an author source by its id only, since activity records are read without the author masking', () => {
    expect(sourceAuditName('source-1', authorSource('source-1', 'identity-1', 'Restricted CERT'))).toEqual('source `source-1`');
    expect(sourceAuditName('source-2', undefined)).toEqual('source `source-2`');
  });

  it('should name the other sources, whose names are never masked', () => {
    const connector = { internal_id: 'source-3', source_kind: SOURCE_KIND_CONNECTOR, ref_id: 'connector-1', name: 'IP reputation feed' } as BasicStoreEntitySource;
    expect(sourceAuditName('source-3', connector)).toEqual('source `IP reputation feed`');
  });
});
