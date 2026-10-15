import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual<typeof import('../../../src/config/conf')>('../../../src/config/conf');
  const originalGet = actual.default.get.bind(actual.default);
  // Small batch size, so the chunking is visible on small graphs
  vi.spyOn(actual.default, 'get').mockImplementation((key?: string) => (key === 'app:live_stream:resolution_batch_size' ? 2 : originalGet(key)));
  return {
    ...actual,
    logApp: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
  };
});
vi.mock('../../../src/database/redis');
vi.mock('../../../src/database/stream/stream-handler', () => ({ createStreamProcessor: vi.fn() }));
vi.mock('../../../src/database/engine', () => ({ elCount: vi.fn(), elList: vi.fn(), elFindByIds: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', () => ({ fullRelationsList: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ stixLoadById: vi.fn(), storeLoadByIdsWithRefs: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({ getEntitiesListFromCache: vi.fn(), getEntityFromCache: vi.fn() }));
// The STIX of a test element is { id, refs }: only what the resolution reads from it
vi.mock('../../../src/database/stix-2-1-converter', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/stix-2-1-converter')>();
  return { ...actual, convertStoreToStix_2_1: vi.fn((element: any) => ({ id: element.standard_id, refs: element.refs })) };
});
vi.mock('../../../src/schema/stixEmbeddedRelationship', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/schema/stixEmbeddedRelationship')>();
  return { ...actual, stixRefsExtractor: vi.fn((stix: any) => stix.refs ?? []) };
});
vi.mock('../../../src/database/data-changes', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/data-changes')>();
  return { ...actual, generateCreateMessage: vi.fn((element: any) => `creates ${element.standard_id}`) };
});

import { LRUCache } from 'lru-cache';
import { storeLoadByIdsWithRefs } from '../../../src/database/middleware';
// eslint-disable-next-line import/extensions
import { resolveMissingReferences } from '../../../src/graphql/sseMiddleware.js';

const BATCH_SIZE = 2;

const context = {} as any;
const user = { id: 'user-id' } as any;

// Store element whose standard_id is its own name, with refs to other elements by name
const buildGraph = (edges: Record<string, string[]>) => {
  const graph: Record<string, any> = {};
  Object.entries(edges).forEach(([id, refs]) => {
    graph[id] = { internal_id: `internal-${id}`, standard_id: id, refs };
  });
  return graph;
};

const mockStore = (graph: Record<string, any>) => {
  vi.mocked(storeLoadByIdsWithRefs).mockImplementation(async (_context, _user, ids) => {
    const elements = (ids as string[]).map((id) => graph[id]).filter((element) => element !== undefined);
    return [...new Set(elements)];
  });
};

const loadedChunks = () => vi.mocked(storeLoadByIdsWithRefs).mock.calls.map(([, , ids]) => ids as string[]);

const resolve = async (missingRefs: string[], opts: { requiredRefs?: string[]; cache?: LRUCache<string, string>; stopAfter?: number } = {}) => {
  const cache = opts.cache ?? new LRUCache<string, string>({ max: 5000 });
  const publishedChunks: string[][] = [];
  const onResolved = vi.fn(async (elements: any[]) => {
    publishedChunks.push(elements.map((element) => element.stix.id));
    return opts.stopAfter === undefined || publishedChunks.length < opts.stopAfter;
  });
  const isComplete = await resolveMissingReferences(context, user, missingRefs, cache, onResolved, { requiredRefs: opts.requiredRefs });
  return { isComplete, publishedChunks, published: publishedChunks.flat(), onResolved };
};

// Every ref of a published element that is itself published must have been published in a previous chunk,
// or in the same one: as before chunking within a level, elements loaded together are not ordered between them.
const expectDependenciesFirst = (graph: Record<string, any>, publishedChunks: string[][]) => {
  const chunkOf = (id: string) => publishedChunks.findIndex((chunk) => chunk.includes(id));
  publishedChunks.flat().forEach((id) => {
    graph[id].refs.filter((ref: string) => chunkOf(ref) !== -1).forEach((ref: string) => {
      expect(chunkOf(ref), `${ref} must be published before ${id}`).toBeLessThanOrEqual(chunkOf(id));
    });
  });
};

describe('resolveMissingReferences', () => {
  beforeEach(() => {
    vi.mocked(storeLoadByIdsWithRefs).mockReset();
  });

  it('should load and publish a large container frontier in bounded chunks', async () => {
    const objects = ['o1', 'o2', 'o3', 'o4', 'o5'];
    const graph = buildGraph({ container: objects, ...Object.fromEntries(objects.map((o) => [o, []])) });
    mockStore(graph);
    const { isComplete, publishedChunks, published } = await resolve(['container']);
    expect(isComplete).toBe(true);
    expect(loadedChunks()).toEqual([['container'], ['o1', 'o2'], ['o3', 'o4'], ['o5']]);
    loadedChunks().forEach((chunk) => expect(chunk.length).toBeLessThanOrEqual(BATCH_SIZE));
    // Each chunk is published as soon as it is resolved, the container only after all its objects
    expect(publishedChunks).toEqual([['o1', 'o2'], ['o3', 'o4'], ['o5'], ['container']]);
    expect(published).toHaveLength(6);
  });

  it('should publish the deepest dependencies first', async () => {
    const graph = buildGraph({ a: ['b'], b: ['c'], c: ['d'], d: [] });
    mockStore(graph);
    const { isComplete, published } = await resolve(['a']);
    expect(isComplete).toBe(true);
    expect(published).toEqual(['d', 'c', 'b', 'a']);
  });

  it('should publish dependencies before dependents across chunks and levels', async () => {
    const graph = buildGraph({
      container: ['r1', 'r2', 'r3', 'r4', 'r5'],
      r1: ['identity', 'marking'],
      r2: ['r5', 'identity'],
      r3: ['r1', 'marking'],
      r4: ['r2', 'r3', 'r5'],
      r5: ['marking'],
      identity: ['marking'],
      marking: [],
    });
    mockStore(graph);
    const { isComplete, published, publishedChunks } = await resolve(['container']);
    expect(isComplete).toBe(true);
    expect([...published].sort()).toEqual(Object.keys(graph).sort());
    expectDependenciesFirst(graph, publishedChunks);
    // Each element is loaded only once, even when referenced from several chunks
    const loaded = loadedChunks().flat();
    expect(loaded).toHaveLength(new Set(loaded).size);
    loadedChunks().forEach((chunk) => expect(chunk.length).toBeLessThanOrEqual(BATCH_SIZE));
  });

  it('should not reload an element already resolved by the dependencies of a previous chunk', async () => {
    // r1 and r3 are in the first chunk, r3 needs r2, which is also part of the second chunk
    const graph = buildGraph({ r1: [], r3: ['r2'], r2: [] });
    mockStore(graph);
    const { published } = await resolve(['r1', 'r3', 'r2']);
    expect(loadedChunks()).toEqual([['r1', 'r3'], ['r2']]);
    expect(published).toEqual(['r2', 'r1', 'r3']);
  });

  it('should resolve elements referenced through any of their ids only once', async () => {
    // a references b through a stix id, c references b through its standard id
    const graph = buildGraph({ a: ['b-alias', 'c'], b: [], c: ['b'] });
    graph.b.x_opencti_stix_ids = ['b-alias'];
    graph['b-alias'] = graph.b;
    mockStore(graph);
    const { published } = await resolve(['a']);
    expect(loadedChunks()).toEqual([['a'], ['b-alias', 'c']]);
    expect(published).toEqual(['b', 'c', 'a']);
  });

  it('should terminate on circular references', async () => {
    const graph = buildGraph({ a: ['b'], b: ['c'], c: ['a'] });
    mockStore(graph);
    const { isComplete, published } = await resolve(['a']);
    expect(isComplete).toBe(true);
    expect(published).toEqual(['c', 'b', 'a']);
  });

  it('should skip refs already in the cache', async () => {
    const graph = buildGraph({ a: ['b', 'c'], b: [], c: [] });
    mockStore(graph);
    const cache = new LRUCache<string, string>({ max: 5000 });
    cache.set('b', 'hit');
    const { published } = await resolve(['a'], { cache });
    expect(loadedChunks().flat()).not.toContain('b');
    expect(published).toEqual(['c', 'a']);
  });

  it('should stop loading when the consumer stops the resolution', async () => {
    const objects = ['o1', 'o2', 'o3', 'o4', 'o5'];
    const graph = buildGraph({ container: objects, ...Object.fromEntries(objects.map((o) => [o, []])) });
    mockStore(graph);
    const { isComplete, publishedChunks } = await resolve(['container'], { stopAfter: 1 });
    expect(isComplete).toBe(false);
    expect(publishedChunks).toEqual([['o1', 'o2']]);
    expect(loadedChunks()).toEqual([['container'], ['o1', 'o2']]);
  });

  describe('with required refs (from and to of a relationship)', () => {
    it('should publish nothing when a required ref is not accessible', async () => {
      const graph = buildGraph({ from: ['marking'], marking: [], creator: [] });
      mockStore(graph);
      const { isComplete, onResolved } = await resolve(['from', 'to', 'creator'], { requiredRefs: ['from', 'to'] });
      expect(isComplete).toBe(false);
      expect(onResolved).not.toHaveBeenCalled();
      // Only the required refs are loaded before giving up
      expect(loadedChunks()).toEqual([['from', 'to']]);
    });

    it('should publish nothing when a required ref is empty', async () => {
      mockStore(buildGraph({ from: [] }));
      const { isComplete, onResolved } = await resolve(['from'], { requiredRefs: ['from', undefined as unknown as string] });
      expect(isComplete).toBe(false);
      expect(onResolved).not.toHaveBeenCalled();
      expect(storeLoadByIdsWithRefs).not.toHaveBeenCalled();
    });

    it('should publish everything when required refs are accessible', async () => {
      const graph = buildGraph({ from: ['marking'], to: ['marking'], marking: [], creator: [] });
      mockStore(graph);
      const { isComplete, published, publishedChunks } = await resolve(['from', 'to', 'creator', 'marking'], { requiredRefs: ['from', 'to'] });
      expect(isComplete).toBe(true);
      expect(loadedChunks()[0]).toEqual(['from', 'to']);
      expect(publishedChunks).toEqual([['marking'], ['from', 'to'], ['creator']]);
      expect([...published].sort()).toEqual(['creator', 'from', 'marking', 'to']);
    });

    it('should accept required refs already in the cache without loading them', async () => {
      mockStore(buildGraph({ to: [], creator: [] }));
      const cache = new LRUCache<string, string>({ max: 5000 });
      cache.set('from', 'hit');
      const { isComplete, published } = await resolve(['from', 'to', 'creator'], { requiredRefs: ['from', 'to'], cache });
      expect(isComplete).toBe(true);
      expect(loadedChunks()).toEqual([['to'], ['creator']]);
      expect(published).toEqual(['to', 'creator']);
    });
  });
});
