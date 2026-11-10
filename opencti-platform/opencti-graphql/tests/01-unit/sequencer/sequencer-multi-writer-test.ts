import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import { ignoreIndexAlreadyExists, NODE_FIELD_MAPPING, ownedPendingQuery, recordOwner } from '../../../src/database/sequencer/sequencer-multi-writer';
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
