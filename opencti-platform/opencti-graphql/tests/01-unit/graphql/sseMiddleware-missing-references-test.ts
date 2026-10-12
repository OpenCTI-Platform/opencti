import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LRUCache } from 'lru-cache';
import * as middleware from '../../../src/database/middleware';
import { resolveMissingReferences } from '../../../src/graphql/sseMiddleware';

vi.mock('../../../src/database/middleware');
vi.mock('../../../src/database/stix-2-1-converter', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/stix-2-1-converter')>()),
  convertStoreToStix_2_1: vi.fn((element: { standard_id: string; refs: string[] }) => ({ id: element.standard_id, refs: element.refs })),
}));
vi.mock('../../../src/schema/stixEmbeddedRelationship', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/schema/stixEmbeddedRelationship')>()),
  stixRefsExtractor: vi.fn((stix: { refs: string[] }) => stix.refs),
}));
vi.mock('../../../src/database/data-changes', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/data-changes')>()),
  generateCreateMessage: vi.fn((element: { name: string }) => `creates ${element.name}`),
}));

// REPORT 01 -- object --> CASE 01 -- object --> CASE 02 -- object --> REPORT 01, both cases created by ADMIN
const element = (name: string, standardId: string, refs: string[]) => ({ internal_id: `${name}-internal-id`, standard_id: standardId, name, refs });
const ELEMENTS = [
  element('Report-01', 'report--01', ['case-incident--01']),
  element('Case-01', 'case-incident--01', ['identity--admin', 'case-incident--02']),
  element('Case-02', 'case-incident--02', ['identity--admin', 'report--01']),
  element('admin', 'identity--admin', []),
];
const BY_ID = new Map(ELEMENTS.map((candidate) => [candidate.standard_id, candidate]));

const resolve = async (searchOrder: 'requested' | 'reversed') => {
  vi.mocked(middleware.storeLoadByIdsWithRefs).mockImplementation(async (_context, _user, ids) => {
    const found = ids.map((id) => BY_ID.get(id)).filter((candidate) => candidate !== undefined);
    return (searchOrder === 'reversed' ? found.reverse() : found) as never;
  });
  const resolved = await resolveMissingReferences({} as never, {} as never, ['case-incident--01'], new LRUCache({ max: 100 }));
  return resolved.map(({ stix }: { stix: { id: string } }) => stix.id);
};

describe('Stream resolution of missing references', () => {
  beforeEach(() => {
    vi.mocked(middleware.storeLoadByIdsWithRefs).mockReset();
  });

  it('should send every missing element once, deepest dependencies first, whatever order the search returns', async () => {
    const expected = ['report--01', 'identity--admin', 'case-incident--02', 'case-incident--01'];
    expect(await resolve('requested')).toEqual(expected);
    // Case 02 returned before the ADMIN individual it references: the individual is resolved one level deeper, and
    // only that occurrence is sent.
    expect(await resolve('reversed')).toEqual(expected);
  });

  it('should not resolve the references already in the cache', async () => {
    vi.mocked(middleware.storeLoadByIdsWithRefs).mockImplementation(async (_context, _user, ids) => ids.map((id) => BY_ID.get(id)) as never);
    const cache = new LRUCache<string, boolean>({ max: 100 });
    cache.set('identity--admin', true);
    const resolved = await resolveMissingReferences({} as never, {} as never, ['case-incident--01'], cache);
    expect(resolved.map(({ stix }: { stix: { id: string } }) => stix.id)).toEqual(['report--01', 'case-incident--02', 'case-incident--01']);
  });
});
