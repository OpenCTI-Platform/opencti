import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import {
  dedupFoundRelationIds,
  ignoreIndexAlreadyExists,
  NODE_FIELD_MAPPING,
  ownedPendingQuery,
  recordOwner,
  relationBasisContext,
  splitPlanOnHeldKeys,
  staleDedupSearches,
} from '../../../src/database/sequencer/sequencer-multi-writer';
import { deferIntents, deferOperation, initPendingIntents, registerPendingIntentsEsOps } from '../../../src/database/sequencer/sequencer-pending-intents';
import { buildPendingRecords, initPendingRefs, registerPendingRefsEsOps } from '../../../src/database/sequencer/sequencer-pending-refs';
import { SequencerIdentityMap } from '../../../src/database/sequencer/sequencer-identity-map';

// Several platforms writing (multi_writer): each owns the retention records it writes and
// rehydrates only those (or the ones written before, without owner); a single writer keeps its
// documents and queries exactly as before.

const saved = { multiWriter: SEQUENCER_CONFIG.multiWriter, nodeId: SEQUENCER_CONFIG.nodeId };
const asWriter = (multiWriter: boolean) => {
  SEQUENCER_CONFIG.multiWriter = multiWriter;
  SEQUENCER_CONFIG.nodeId = 'node-a';
};
afterEach(() => {
  SEQUENCER_CONFIG.multiWriter = saved.multiWriter;
  SEQUENCER_CONFIG.nodeId = saved.nodeId;
});

const intentOf = (name: string) => ({
  id: name, kind: 'entity', type: 'Malware', input: { name }, user: { id: 'u1' }, context: {}, opts: {}, arrivedAt: 0, source: 's', sizeBytes: 1, candidateIds: [], referencedIds: [],
}) as any;

describe('record owner', () => {
  it('should mark a record with its node on a multi writer only', () => {
    asWriter(true);
    expect(recordOwner()).toEqual({ node: 'node-a' });
    asWriter(false);
    expect(recordOwner()).toEqual({});
  });

  it('should rehydrate the records of this node or of no node on a multi writer, every pending one otherwise', () => {
    expect(ownedPendingQuery(false, 'node-a')).toEqual({ term: { status: 'pending' } });
    const query = ownedPendingQuery(true, 'node-a');
    expect(query.bool.filter[0]).toEqual({ term: { status: 'pending' } });
    expect(query.bool.filter[1]).toEqual({
      bool: { should: [{ term: { node: 'node-a' } }, { bool: { must_not: { exists: { field: 'node' } } } }], minimum_should_match: 1 },
    });
  });
});

describe('concurrent creation of a store index', () => {
  it('should go on when the index was created by another platform, and fail on anything else', () => {
    expect(ignoreIndexAlreadyExists({ meta: { body: { error: { type: 'resource_already_exists_exception' } } } })).toBeNull();
    expect(ignoreIndexAlreadyExists({ body: { error: { type: 'resource_already_exists_exception' } } })).toBeNull();
    expect(ignoreIndexAlreadyExists(new Error('[resource_already_exists_exception] index already exists'))).toBeNull();
    expect(() => ignoreIndexAlreadyExists({ meta: { body: { error: { type: 'mapper_parsing_exception' } } } })).toThrow();
    expect(() => ignoreIndexAlreadyExists(new Error('connect ECONNREFUSED'))).toThrow();
  });
});

describe('pending intents store on a multi writer', () => {
  it('should persist the owner of a new intent record and of a new operation record, none on a single writer', async () => {
    const bulk = vi.fn().mockResolvedValue({ errors: false, items: [] });
    registerPendingIntentsEsOps({ indexExists: vi.fn(), createIndex: vi.fn(), bulk, search: vi.fn() });
    asWriter(true);
    await deferIntents([{ intent: intentOf('owned-1'), missing: ['malware--x'] }]);
    expect(bulk.mock.calls[0][0][1].node).toEqual('node-a');
    await deferOperation({ operation: { query: 'mutation M { a }', variables: { n: 'owned-2' } }, envelope: {} as any, user: { id: 'u1' } as any, missing: ['malware--y'] });
    expect(bulk.mock.calls[1][0][1].node).toEqual('node-a');
    asWriter(false);
    await deferIntents([{ intent: intentOf('single-1'), missing: ['malware--x'] }]);
    expect(bulk.mock.calls[2][0][1]).not.toHaveProperty('node');
  });

  it('should map the owner and rehydrate its own records only on a multi writer', async () => {
    const putMapping = vi.fn().mockResolvedValue(undefined);
    const search = vi.fn().mockResolvedValue({ hits: { hits: [] } });
    registerPendingIntentsEsOps({ indexExists: vi.fn().mockResolvedValue(true), createIndex: vi.fn(), bulk: vi.fn(), search, putMapping });
    asWriter(true);
    await initPendingIntents();
    expect(putMapping).toHaveBeenCalledWith('opencti_sequencer_pending_intents', NODE_FIELD_MAPPING);
    expect(search.mock.calls[0][0].query).toEqual(ownedPendingQuery(true, 'node-a'));
    asWriter(false);
    await initPendingIntents();
    expect(putMapping).toHaveBeenCalledTimes(1);
    expect(search.mock.calls[1][0].query).toEqual({ term: { status: 'pending' } });
  });

  it('should create a new index with the owner mapped', async () => {
    const createIndex = vi.fn().mockResolvedValue(null);
    registerPendingIntentsEsOps({ indexExists: vi.fn().mockResolvedValue(false), createIndex, bulk: vi.fn(), search: vi.fn() });
    await initPendingIntents();
    expect(createIndex.mock.calls[0][1]).toMatchObject(NODE_FIELD_MAPPING);
  });
});

describe('pending refs store on a multi writer', () => {
  const strip = { ownerId: 'o1', ownerType: 'Report', relType: 'object', targetRef: 'malware--x', userId: 'u1' };

  it('should persist the owner of a strip record on a multi writer only', () => {
    asWriter(true);
    expect(buildPendingRecords([strip])[0].node).toEqual('node-a');
    asWriter(false);
    expect(buildPendingRecords([strip])[0]).not.toHaveProperty('node');
  });

  it('should map the owner and rehydrate its own records only on a multi writer', async () => {
    const putMapping = vi.fn().mockResolvedValue(undefined);
    const search = vi.fn().mockResolvedValue({ hits: { hits: [] } });
    registerPendingRefsEsOps({ indexExists: vi.fn().mockResolvedValue(true), createIndex: vi.fn(), bulk: vi.fn(), search, putMapping });
    asWriter(true);
    await initPendingRefs();
    expect(putMapping).toHaveBeenCalledWith('opencti_sequencer_pending_refs', NODE_FIELD_MAPPING);
    expect(search.mock.calls[0][0].query).toEqual(ownedPendingQuery(true, 'node-a'));
    asWriter(false);
    await initPendingRefs();
    expect(search.mock.calls[1][0].query).toEqual({ term: { status: 'pending' } });
  });
});

describe('ids found absent by the resolution', () => {
  beforeEach(() => {
    SEQUENCER_CONFIG.mode = 'batch';
  });

  it('should list each id the batch found absent once, typed or not, and none after the clear', () => {
    const map = new SequencerIdentityMap();
    map.markAbsent(['malware--a', 'malware--b'], null);
    map.markAbsent(['malware--b', 'tool--c'], ['Tool']);
    expect(map.knownAbsentIds().sort()).toEqual(['malware--a', 'malware--b', 'tool--c']);
    map.clearAbsent();
    expect(map.knownAbsentIds()).toEqual([]);
  });
});

// task 0040 defect 2: a platform's bare copy of a relation can predate another platform's upsert;
// diffing against it erased the stix ids that platform appended
describe('relation upsert basis on a multi writer', () => {
  const resolutions = (withRefs: string[]) => ({ hasWithRefs: (id: string) => withRefs.includes(id), serveBare: vi.fn() });
  const applying = (withRefs: string[]) => ({ user: 'u', sequencer: { scope: 'applying', resolutions: resolutions(withRefs) } });

  it('should read the basis without the identity map unless the batch holds a with-refs copy', () => {
    const context = applying(['rel-batch']);
    const outside = relationBasisContext(context, 'rel-other', true);
    expect(outside.sequencer.resolutions).toBeUndefined();
    expect(outside.sequencer.scope).toEqual('applying');
    expect(outside.user).toEqual('u');
    expect(relationBasisContext(context, 'rel-batch', true)).toBe(context);
  });

  it('should keep the context of a single writer and of a write outside the sequencer', () => {
    const context = applying([]);
    expect(relationBasisContext(context, 'rel-other', false)).toBe(context);
    const plain = { user: 'u' } as { user: string; sequencer?: undefined };
    expect(relationBasisContext(plain, 'rel-other', true)).toBe(plain);
  });

  it('should list each relation the dedup prefetch found once', () => {
    const prefetch = [
      { existing: [{ internal_id: 'rel-a' }, { internal_id: 'rel-b' }] },
      { existing: [{ internal_id: 'rel-a' }, {}] },
      { existing: [] },
    ];
    expect(dedupFoundRelationIds(prefetch).sort()).toEqual(['rel-a', 'rel-b']);
  });
});

describe('step B2: dedup searches made before the batch lock', () => {
  const keyOf = new Map([['s1', 'relation-dedup:targets:a:b'], ['s2', 'relation-dedup:targets:a:c'], ['s3', 'relation-dedup:targets:a:b']]);

  it('should keep every search whose key was not stamped since', () => {
    const before = new Map([['relation-dedup:targets:a:b', 'x'], ['relation-dedup:targets:a:c', '']]);
    expect(staleDedupSearches(keyOf, before, new Map(before))).toEqual({ stale: [], changedKeys: 0 });
  });

  it('should search again every search on a key another platform stamped since, a first stamp included', () => {
    const before = new Map([['relation-dedup:targets:a:b', 'x'], ['relation-dedup:targets:a:c', '']]);
    const now = new Map([['relation-dedup:targets:a:b', 'y'], ['relation-dedup:targets:a:c', 'z']]);
    expect(staleDedupSearches(keyOf, before, now)).toEqual({ stale: ['s1', 's2', 's3'], changedKeys: 2 });
  });

  it('should search again a search whose key had no stamp read before it, or has none now', () => {
    const before = new Map([['relation-dedup:targets:a:b', 'x']]);
    expect(staleDedupSearches(keyOf, before, new Map(before)).stale).toEqual(['s2']);
    expect(staleDedupSearches(keyOf, before, new Map()).stale).toEqual(['s1', 's2', 's3']);
  });
});

describe('partial acquire: groups carried when another platform holds one of their keys', () => {
  const group = (name: string, keys: string[], dependsOn?: number[], replans = 0) => ({ name, keys, leader: { replans }, dependsOn });
  const keysOf = (g: { keys: string[] }) => g.keys;

  it('should carry the conflicting group and its dependents, keep the rest with remapped dependencies', () => {
    const order = [
      group('author', ['identity--nvd']),
      group('vuln', ['vulnerability--1']),
      group('rel-on-author', ['relation-dedup:x'], [0]),
      group('rel-on-vuln', ['relation-dedup:y'], [1]),
      group('chained', ['report--1'], [2]),
    ];
    const { kept, carried } = splitPlanOnHeldKeys(order, keysOf, new Set(['identity--nvd']), 3);
    expect(carried.map((g) => g.name)).toEqual(['author', 'rel-on-author', 'chained']);
    expect(kept.map((g) => g.name)).toEqual(['vuln', 'rel-on-vuln']);
    expect(kept[1].dependsOn).toEqual([0]);
    expect(order[3].dependsOn).toEqual([1]); // the plan's groups are not mutated
  });

  it('should carry nothing when nothing is held, when every group conflicts, or when a conflicting group was carried enough', () => {
    const order = [group('a', ['k1']), group('b', ['k2'], [0])];
    expect(splitPlanOnHeldKeys(order, keysOf, new Set(), 3).carried).toEqual([]);
    expect(splitPlanOnHeldKeys(order, keysOf, new Set(['k1']), 3).carried).toEqual([]); // b depends on a: every group
    const starving = [group('a', ['k1'], undefined, 3), group('b', ['k2'])];
    expect(splitPlanOnHeldKeys(starving, keysOf, new Set(['k1']), 3)).toEqual({ kept: starving, carried: [] });
  });
});
