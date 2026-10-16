import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// Small batch size, so the chunking is visible on small graphs. Read when sseMiddleware is imported.
const batchConfig = vi.hoisted(() => ({ size: 2 }));

vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual<typeof import('../../../src/config/conf')>('../../../src/config/conf');
  const originalGet = actual.default.get.bind(actual.default);
  vi.spyOn(actual.default, 'get').mockImplementation((key?: string) => (key === 'app:live_stream:resolution_batch_size' ? batchConfig.size : originalGet(key)));
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

// Modules under test, reloaded by the suites running with another batch size
let loadByIdsWithRefs = vi.mocked(storeLoadByIdsWithRefs);
let resolveReferences = resolveMissingReferences;

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
  loadByIdsWithRefs.mockImplementation(async (_context, _user, ids) => {
    const elements = (ids as string[]).map((id) => graph[id]).filter((element) => element !== undefined);
    return [...new Set(elements)];
  });
};

const loadedChunks = () => loadByIdsWithRefs.mock.calls.map(([, , ids]) => ids as string[]);

const resolve = async (missingRefs: string[], opts: { requiredRefs?: string[]; cache?: LRUCache<string, string>; stopAfter?: number } = {}) => {
  const cache = opts.cache ?? new LRUCache<string, string>({ max: 5000 });
  const publishedChunks: string[][] = [];
  const onResolved = vi.fn(async (elements: any[]) => {
    publishedChunks.push(elements.map((element) => element.stix.id));
    return opts.stopAfter === undefined || publishedChunks.length < opts.stopAfter;
  });
  const isComplete = await resolveReferences(context, user, missingRefs, cache, onResolved, { requiredRefs: opts.requiredRefs });
  return { isComplete, publishedChunks, published: publishedChunks.flat(), onResolved };
};

// Every ref of a published element that is itself published must have been published before it
const expectDependenciesFirst = (graph: Record<string, any>, published: string[]) => {
  published.forEach((id, position) => {
    graph[id].refs.filter((ref: string) => published.includes(ref)).forEach((ref: string) => {
      expect(published.indexOf(ref), `${ref} must be published before ${id}`).toBeLessThan(position);
    });
  });
};

describe('resolveMissingReferences', () => {
  beforeEach(() => {
    loadByIdsWithRefs.mockReset();
  });

  it('should load and publish a large container frontier in bounded chunks', async () => {
    const objects = ['o1', 'o2', 'o3', 'o4', 'o5'];
    const graph = buildGraph({ container: objects, ...Object.fromEntries(objects.map((o) => [o, []])) });
    mockStore(graph);
    const { isComplete, publishedChunks, published } = await resolve(['container']);
    expect(isComplete).toBe(true);
    expect(loadedChunks()).toEqual([['container'], ['o1', 'o2'], ['o3', 'o4'], ['o5']]);
    loadedChunks().forEach((chunk) => expect(chunk.length).toBeLessThanOrEqual(BATCH_SIZE));
    // Elements are published in chunks as soon as they are ready, the container only after all its objects
    expect(publishedChunks).toEqual([['o1', 'o2'], ['o3', 'o4'], ['o5', 'container']]);
    publishedChunks.forEach((chunk) => expect(chunk.length).toBeLessThanOrEqual(BATCH_SIZE));
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
    const { isComplete, published } = await resolve(['container']);
    expect(isComplete).toBe(true);
    expect([...published].sort()).toEqual(Object.keys(graph).sort());
    expectDependenciesFirst(graph, published);
    // Each element is loaded only once, even when referenced from several chunks
    const loaded = loadedChunks().flat();
    expect(loaded).toHaveLength(new Set(loaded).size);
    loadedChunks().forEach((chunk) => expect(chunk.length).toBeLessThanOrEqual(BATCH_SIZE));
  });

  it('should not reload an element already resolved as the dependency of a previous one', async () => {
    // r1 and r3 are loaded together, r3 needs r2, which comes after them in the frontier
    const graph = buildGraph({ r1: [], r3: ['r2'], r2: [] });
    mockStore(graph);
    const { published } = await resolve(['r1', 'r3', 'r2']);
    expect(loadedChunks()).toEqual([['r1', 'r3'], ['r2']]);
    expect(published).toEqual(['r1', 'r2', 'r3']);
  });

  it('should publish a dependency loaded in the same chunk before its dependent', async () => {
    // rel is loaded together with source, which comes after it in the container
    const graph = buildGraph({ container: ['rel', 'source', 'target'], rel: ['source', 'target'], source: [], target: [] });
    mockStore(graph);
    const { published } = await resolve(['container']);
    expect(loadedChunks()).toEqual([['container'], ['rel', 'source'], ['target']]);
    expect(published).toEqual(['source', 'target', 'rel', 'container']);
  });

  it('should publish a dependency loaded by an ancestor chunk before its dependent', async () => {
    // a and b are loaded together, b is only needed deeper, by d
    const graph = buildGraph({ a: ['d'], b: [], d: ['b'] });
    mockStore(graph);
    const { published } = await resolve(['a', 'b']);
    expect(loadedChunks()).toEqual([['a', 'b'], ['d']]);
    expect(published).toEqual(['b', 'd', 'a']);
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

  it('should publish elements referenced only through an alias id', async () => {
    // a references b through one of its aliases only, which the load matches but the stix ids do not hold
    const graph = buildGraph({ a: ['b-alias'], b: [] });
    graph.b.i_aliases_ids = ['b-alias'];
    graph['b-alias'] = graph.b;
    mockStore(graph);
    const { isComplete, published } = await resolve(['a']);
    expect(isComplete).toBe(true);
    expect(loadedChunks()).toEqual([['a'], ['b-alias']]);
    expect(published).toEqual(['b', 'a']);
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
      expect(loadedChunks()).toEqual([['from', 'to'], ['marking'], ['creator']]);
      expect(publishedChunks).toEqual([['marking', 'from'], ['to', 'creator']]);
      expectDependenciesFirst(graph, published);
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

  describe('with a batch size of one', () => {
    beforeAll(async () => {
      batchConfig.size = 1;
      vi.resetModules();
      loadByIdsWithRefs = vi.mocked((await import('../../../src/database/middleware')).storeLoadByIdsWithRefs);
      // eslint-disable-next-line import/extensions
      resolveReferences = (await import('../../../src/graphql/sseMiddleware.js')).resolveMissingReferences;
    });

    afterAll(() => {
      batchConfig.size = BATCH_SIZE;
      loadByIdsWithRefs = vi.mocked(storeLoadByIdsWithRefs);
      resolveReferences = resolveMissingReferences;
    });

    it('should load required refs one by one before publishing anything', async () => {
      const graph = buildGraph({ from: ['marking'], to: ['marking'], marking: [] });
      mockStore(graph);
      const { isComplete, publishedChunks } = await resolve(['from', 'to', 'marking'], { requiredRefs: ['from', 'to'] });
      expect(isComplete).toBe(true);
      expect(loadedChunks()).toEqual([['from'], ['to'], ['marking']]);
      expect(publishedChunks).toEqual([['marking'], ['from'], ['to']]);
    });

    it('should stop at the first required ref not accessible', async () => {
      mockStore(buildGraph({ to: [] }));
      const { isComplete, onResolved } = await resolve(['from', 'to'], { requiredRefs: ['from', 'to'] });
      expect(isComplete).toBe(false);
      expect(onResolved).not.toHaveBeenCalled();
      expect(loadedChunks()).toEqual([['from']]);
    });

    it('should not reload a required ref already loaded through another of its ids', async () => {
      const graph = buildGraph({ from: [] });
      graph.from.x_opencti_stix_ids = ['from-alias'];
      graph['from-alias'] = graph.from;
      mockStore(graph);
      const { isComplete, published } = await resolve(['from'], { requiredRefs: ['from', 'from-alias'] });
      expect(isComplete).toBe(true);
      expect(loadedChunks()).toEqual([['from']]);
      expect(published).toEqual(['from']);
    });
  });
});
