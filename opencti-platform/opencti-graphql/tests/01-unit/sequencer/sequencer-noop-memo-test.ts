import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  isNoopOfServedBasis,
  NoopMemo,
  NoopMemoDiag,
  noopMemoKey,
  noopRecordOf,
  noopTokenOf,
  sameNoopToken,
  settleNoopRecords,
  takeNoopMemoHits,
} from '../../../src/database/sequencer/sequencer-noop-memo';
import type { NoopRecord, NoopTarget, NoopToken, NoopVersionsOf } from '../../../src/database/sequencer/sequencer-noop-memo';
import { buildIntent } from '../../../src/database/sequencer/sequencer-intent';
import { SequencerIdentityMap } from '../../../src/database/sequencer/sequencer-identity-map';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import { sequencerScopedContext } from '../../../src/database/sequencer/sequencer-eligibility';
import { executionContext } from '../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// The no-op memo settles an intent with a recorded result only while that result can be nothing
// else: same input, same user, the target still at the version its no-op was compared with, no
// other writer of the target in the batch. Each test below names the wrong settlement it guards
// against.

const intentOf = (args: {
  kind?: 'entity' | 'relation';
  type?: string;
  input?: Record<string, any>;
  candidateIds?: string[];
  context?: Record<string, any>;
  opts?: Record<string, any>;
  user?: Record<string, any>;
}) => buildIntent({
  kind: args.kind ?? 'entity',
  type: args.type ?? 'External-Reference',
  input: args.input ?? { source_name: 'mitre-attack', url: 'https://attack.mitre.org/techniques/T1059' },
  user: (args.user ?? { id: 'u1', origin: { applicant_id: 'conn1' } }) as unknown as AuthUser,
  context: (args.context ?? {}) as unknown as AuthContext,
  opts: args.opts ?? {},
  candidateIds: args.candidateIds ?? ['external-reference--1'],
  apply: async () => null,
});

const basisOf = (internalId: string, standardId: string, extra: Record<string, any> = {}) => ({
  internal_id: internalId,
  standard_id: standardId,
  entity_type: 'External-Reference',
  parent_types: ['Stix-Meta-Object'],
  ...extra,
});

describe('noopMemoKey: eligibility and canonical input', () => {
  it('should key an entity create by user, type and input, whatever the key order', () => {
    const a = noopMemoKey(intentOf({ input: { url: 'u', source_name: 's' } }));
    const b = noopMemoKey(intentOf({ input: { source_name: 's', url: 'u' } }));
    expect(a).not.toBeNull();
    expect(a).toEqual(b);
  });

  it('should give different keys to different users, types and inputs', () => {
    const base = noopMemoKey(intentOf({}));
    expect(noopMemoKey(intentOf({ user: { id: 'u2' } }))).not.toEqual(base);
    expect(noopMemoKey(intentOf({ type: 'Label' }))).not.toEqual(base);
    expect(noopMemoKey(intentOf({ input: { source_name: 'mitre-attack', url: 'https://attack.mitre.org/techniques/T1058' } }))).not.toEqual(base);
    // a number and its text, null and undefined, nested values
    expect(noopMemoKey(intentOf({ input: { x: 1 } }))).not.toEqual(noopMemoKey(intentOf({ input: { x: '1' } })));
    expect(noopMemoKey(intentOf({ input: { x: null } }))).not.toEqual(noopMemoKey(intentOf({ input: { x: undefined } })));
    expect(noopMemoKey(intentOf({ input: { x: [{ a: 1 }] } }))).not.toEqual(noopMemoKey(intentOf({ input: { x: [{ a: 2 }] } })));
  });

  it('should key a GraphQL input (null prototype objects, nested too) as its plain copy', () => {
    const nested = Object.assign(Object.create(null), { source_name: 's', url: 'u' });
    const input = Object.assign(Object.create(null), { name: 'NIST NVD', externalReferences: [nested] });
    const key = noopMemoKey(intentOf({ input }));
    expect(key).not.toBeNull();
    expect(key).toEqual(noopMemoKey(intentOf({ input: { name: 'NIST NVD', externalReferences: [{ source_name: 's', url: 'u' }] } })));
  });

  it('should tell two dates apart (an object walk would read both as {})', () => {
    const first = noopMemoKey(intentOf({ input: { created: new Date('2024-01-01T00:00:00.000Z') } }));
    const second = noopMemoKey(intentOf({ input: { created: new Date('2025-01-01T00:00:00.000Z') } }));
    expect(first).not.toBeNull();
    expect(first).not.toEqual(second);
    expect(noopMemoKey(intentOf({ input: { created: new Date('invalid') } }))).toBeNull();
  });

  it('should key a complete create apart from a plain one (markings are created complete)', () => {
    const complete = noopMemoKey(intentOf({ opts: { complete: true } }));
    expect(complete).not.toBeNull();
    expect(complete).not.toEqual(noopMemoKey(intentOf({})));
    expect(noopMemoKey(intentOf({ opts: { complete: false } }))).toEqual(noopMemoKey(intentOf({})));
  });

  it('should refuse relations, other opts, replay contexts and drafts', () => {
    expect(noopMemoKey(intentOf({ kind: 'relation' }))).toBeNull();
    expect(noopMemoKey(intentOf({ opts: { complete: true, noEnrichOnUpdate: true } }))).toBeNull();
    expect(noopMemoKey(intentOf({ opts: { references: [] } }))).toBeNull();
    expect(noopMemoKey(intentOf({ context: { eventId: '1-0' } }))).toBeNull();
    expect(noopMemoKey(intentOf({ context: { synchronizedUpsert: true } }))).toBeNull();
    expect(noopMemoKey(intentOf({ context: { draft_context: 'draft1' } }))).toBeNull();
    expect(noopMemoKey(intentOf({ user: { id: 'u1', draft_context: 'draft1' } }))).toBeNull();
  });

  it('should refuse inputs with side effects on a no-op: files, data URIs, non plain values', () => {
    class Upload {
      constructor(readonly name: string) {}
    }
    expect(noopMemoKey(intentOf({ input: { source_name: 's', files: [new Upload('a.pdf')] } }))).toBeNull();
    expect(noopMemoKey(intentOf({ input: { source_name: 's', file: Promise.resolve({}) } }))).toBeNull();
    expect(noopMemoKey(intentOf({ input: { source_name: 's', description: 'see ![x](data:image/png;base64,AAAA)' } }))).toBeNull();
    expect(noopMemoKey(intentOf({ input: { source_name: 's', nested: [{ text: 'data:text/plain,x' }] } }))).toBeNull();
    expect(noopMemoKey(intentOf({ input: { source_name: 's', when: new Map() } }))).toBeNull();
  });
});

// A token: the version, and the hash of a source named by `content` (same content, same hash)
const tok = (version: string, content = 'v1'): NoopToken => ({ version, hash: `h-${content}` });
const recordOf = (key: string, basis: Record<string, any>, version = '7:1') => noopRecordOf(key, { _index: 'idx', ...basis }, { _index: 'idx', ...basis }, tok(version)) as NoopRecord;

// The stored versions a fake engine serves, by internal id; every read is logged
// stored versions as 'seq:term' (source unchanged, hash of 'v1') or as tokens
const versionsServer = (initial: Record<string, string | NoopToken>) => {
  const versions = new Map(Object.entries(initial).map(([id, v]) => [id, typeof v === 'string' ? tok(v) : v]));
  const reads: NoopTarget[][] = [];
  const versionsOf: NoopVersionsOf = async (targets) => {
    reads.push(targets);
    return new Map(targets.flatMap(({ id }) => (versions.has(id) ? [[id, versions.get(id) as NoopToken] as const] : [])));
  };
  return { versions, reads, versionsOf };
};

describe('noopRecordOf: what a no-op apply leaves to record', () => {
  it('should carry the target, its index, its ids and the version read before the basis', () => {
    const basis = { _index: 'idx', ...basisOf('i1', 'external-reference--1', { x_opencti_stix_ids: ['external-reference--old'] }) };
    const record = noopRecordOf('k', basis, basis, tok('7:1'));
    expect(record).toMatchObject({ key: 'k', targetId: 'i1', targetIndex: 'idx', token: tok('7:1'), result: basis });
    expect(record?.targetIds).toEqual(expect.arrayContaining(['i1', 'external-reference--1', 'external-reference--old']));
  });

  it('should refuse a basis without a version read before it, a result of another element, a basis without index', () => {
    const basis = { _index: 'idx', ...basisOf('i1', 'external-reference--1') };
    expect(noopRecordOf('k', basis, basis, undefined)).toBeNull();
    expect(noopRecordOf('k', basis, { ...basis, internal_id: 'i2' }, tok('7:1'))).toBeNull();
    expect(noopRecordOf('k', basisOf('i1', 'external-reference--1'), basisOf('i1', 'external-reference--1'), tok('7:1'))).toBeNull();
  });

  it('should read the target of a complete result under its element', () => {
    const basis = { _index: 'idx', ...basisOf('i1', 'marking-definition--1') };
    const complete = { element: basis, isCreation: false, event: null };
    expect(noopRecordOf('k', basis, complete, tok('7:1'))).toMatchObject({ targetId: 'i1', result: complete });
  });
});

describe('NoopMemo: bounded store', () => {
  it('should drop the least recently used entry past its size', () => {
    const memo = new NoopMemo(2);
    const basis = basisOf('i1', 'external-reference--1');
    memo.record(recordOf('a', basis));
    memo.record(recordOf('b', basis));
    expect(memo.get('a')).toBeDefined(); // a is now the most recent
    memo.record(recordOf('c', basis));
    expect(memo.size()).toEqual(2);
    expect(memo.get('b')).toBeUndefined();
    expect(memo.get('a')).toBeDefined();
    expect(memo.get('c')).toBeDefined();
  });
});

describe('settleNoopRecords: record only a no-op of the version read before its basis', () => {
  const basis = basisOf('i1', 'external-reference--1', { x_opencti_stix_ids: ['external-reference--alias'] });

  it('should keep a record whose target kept its version, in one read for the batch', async () => {
    const { reads, versionsOf } = versionsServer({ i1: '7:1', i2: '3:1' });
    const records = [recordOf('a', basis), recordOf('b', basis), recordOf('c', basisOf('i2', 'external-reference--2'), '3:1')];
    const { kept, dropped } = await settleNoopRecords(records, [], versionsOf);
    expect(kept.map((r) => r.key)).toEqual(['a', 'b', 'c']);
    expect(dropped).toEqual(0);
    expect(reads).toEqual([[{ id: 'i1', index: 'idx' }, { id: 'i2', index: 'idx' }]]);
  });

  it('should drop a record whose target changed after its basis was read (an attribute, another platform)', async () => {
    const { versionsOf } = versionsServer({ i1: tok('9:1', 'v2') });
    const { kept, dropped } = await settleNoopRecords([recordOf('a', basis)], [], versionsOf);
    expect(kept).toEqual([]);
    expect(dropped).toEqual(1);
  });

  it('should drop a record whose target this batch wrote, through any of its ids, without reading it', async () => {
    const { reads, versionsOf } = versionsServer({ i1: '7:1' });
    const { kept, dropped } = await settleNoopRecords([recordOf('a', basis)], ['external-reference--alias'], versionsOf);
    expect(kept).toEqual([]);
    expect(dropped).toEqual(1);
    expect(reads).toEqual([]);
  });

  it('should drop a record whose target is gone (merged, deleted) or whose primary term changed', async () => {
    expect((await settleNoopRecords([recordOf('a', basis)], [], versionsServer({}).versionsOf)).kept).toEqual([]);
    expect((await settleNoopRecords([recordOf('a', basis)], [], versionsServer({ i1: tok('7:2', 'v2') }).versionsOf)).kept).toEqual([]);
  });

  it('should keep a record whose version moved but whose source without rel_* and refreshed_at did not (a citing entity appended a ref)', async () => {
    const { kept, hashMatches } = await settleNoopRecords([recordOf('a', basis)], [], versionsServer({ i1: tok('9:1', 'v1') }).versionsOf);
    expect(kept.map((r) => r.key)).toEqual(['a']);
    expect(hashMatches).toEqual(1);
  });
});

describe('takeNoopMemoHits: settle only what can be nothing else', () => {
  const setup = (stored: Record<string, string | NoopToken> = { i1: '7:1' }) => {
    const memo = new NoopMemo(100);
    const basis = basisOf('i1', 'external-reference--1');
    const key = noopMemoKey(intentOf({})) as string;
    memo.record(recordOf(key, basis));
    return { memo, key, ...versionsServer(stored), keys: new WeakMap(), types: new Set(['External-Reference']) };
  };

  it('should settle a repeat while the target keeps the recorded version, the rest in batch order', async () => {
    const { memo, versionsOf, reads, keys, types } = setup();
    const before = intentOf({ type: 'Malware', input: { name: 'm1' }, candidateIds: ['malware--1'] });
    const repeat = intentOf({});
    const after = intentOf({ type: 'Malware', input: { name: 'm2' }, candidateIds: ['malware--2'] });
    const { hits, rest } = await takeNoopMemoHits([before, repeat, after], memo, versionsOf, keys, types);
    expect(hits.map((h) => h.intent)).toEqual([repeat]);
    expect(hits[0].result).toMatchObject({ internal_id: 'i1' });
    expect(rest).toEqual([before, after]);
    expect(keys.get(repeat)).toEqual(noopMemoKey(repeat));
    expect(reads).toEqual([[{ id: 'i1', index: 'idx' }]]);
  });

  it('should not settle once the target changed or is gone, and forget the entry', async () => {
    const changed = setup({ i1: tok('8:1', 'v2') });
    const first = await takeNoopMemoHits([intentOf({})], changed.memo, changed.versionsOf, changed.keys, changed.types);
    expect(first.hits).toEqual([]);
    expect(first.misses.tokenChanged).toEqual(1);
    expect(changed.memo.get(changed.key)).toBeUndefined();
    const gone = setup({});
    expect((await takeNoopMemoHits([intentOf({})], gone.memo, gone.versionsOf, gone.keys, gone.types)).hits).toEqual([]);
  });

  it('should settle when only refs appended by citing entities moved the version', async () => {
    const appended = setup({ i1: tok('8:1', 'v1') });
    const { hits, misses } = await takeNoopMemoHits([intentOf({})], appended.memo, appended.versionsOf, appended.keys, appended.types);
    expect(hits).toHaveLength(1);
    expect(misses.hashMatches).toEqual(1);
  });

  it('should not read any version when no intent has an entry', async () => {
    const { memo, versionsOf, reads, keys, types } = setup();
    const { hits, misses } = await takeNoopMemoHits([intentOf({ input: { source_name: 'other' } })], memo, versionsOf, keys, types);
    expect(hits).toEqual([]);
    expect(misses.noEntry).toEqual(1);
    expect(reads).toEqual([]);
  });

  it('should not settle when another entity intent of the batch may write the target', async () => {
    const { memo, versionsOf, keys, types } = setup();
    const repeat = intentOf({});
    // same target by its standard id, another input: it applies, the repeat is no longer a known no-op
    const writer = intentOf({ input: { source_name: 'mitre-attack', url: 'https://attack.mitre.org/techniques/T1059', description: 'new' } });
    const { hits, rest, misses } = await takeNoopMemoHits([repeat, writer], memo, versionsOf, keys, types);
    expect(hits).toEqual([]);
    expect(rest).toEqual([repeat, writer]);
    expect(misses.inBatchWriter).toEqual(1);
  });

  it('should see a writer reaching the target through another of its ids', async () => {
    const memo = new NoopMemo(100);
    const basis = basisOf('i1', 'external-reference--1', { x_opencti_stix_ids: ['external-reference--alias'] });
    memo.record(recordOf(noopMemoKey(intentOf({})) as string, basis));
    const writer = intentOf({ input: { other: true }, candidateIds: ['external-reference--zzz', 'external-reference--alias'] });
    const { hits } = await takeNoopMemoHits([intentOf({}), writer], memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set(['External-Reference']));
    expect(hits).toEqual([]);
  });

  it('should settle two repeats of one target together, and ignore relations to it', async () => {
    const { memo, versionsOf, reads, keys, types } = setup();
    const first = intentOf({});
    const second = intentOf({});
    const relation = intentOf({ kind: 'relation', type: 'external-reference', input: { fromId: 'malware--1', toId: 'external-reference--1' }, candidateIds: ['malware--1', 'external-reference--1'] });
    const { hits, rest } = await takeNoopMemoHits([first, relation, second], memo, versionsOf, keys, types);
    expect(hits.map((h) => h.intent)).toEqual([first, second]);
    expect(rest).toEqual([relation]);
    expect(reads).toEqual([[{ id: 'i1', index: 'idx' }]]);
  });

  it('should compute no key for a type no apply ended as a no-op yet', async () => {
    const { memo, versionsOf, keys } = setup();
    const repeat = intentOf({});
    const { hits } = await takeNoopMemoHits([repeat], memo, versionsOf, keys, new Set(['Label']));
    expect(hits).toEqual([]);
    expect(keys.has(repeat)).toBe(false);
  });

  it('should key an ineligible intent nowhere and never settle it', async () => {
    const { memo, versionsOf, keys, types } = setup();
    const withOpts = intentOf({ opts: { references: ['x'] } });
    const { hits, rest, misses } = await takeNoopMemoHits([withOpts], memo, versionsOf, keys, types);
    expect(hits).toEqual([]);
    expect(rest).toEqual([withOpts]);
    expect(keys.has(withOpts)).toBe(false);
    expect(misses.ineligible).toEqual(1);
  });
});

describe('noop token: version, or source without rel_* and refreshed_at', () => {
  it('should hash a source independently of its key order, and tell different sources apart', () => {
    expect(noopTokenOf(1, 1, { a: 1, b: [1, { c: 2 }] }).hash).toEqual(noopTokenOf(2, 1, { b: [1, { c: 2 }], a: 1 }).hash);
    expect(noopTokenOf(1, 1, { a: 1 }).hash).not.toEqual(noopTokenOf(1, 1, { a: 2 }).hash);
    expect(noopTokenOf(7, 3, {}).version).toEqual('7:3');
  });

  it('should hold on the same version or the same hash, never on an absent document', () => {
    expect(sameNoopToken(tok('1:1', 'x'), tok('1:1', 'y'))).toBe(true);
    expect(sameNoopToken(tok('2:1', 'x'), tok('1:1', 'x'))).toBe(true);
    expect(sameNoopToken(tok('2:1', 'y'), tok('1:1', 'x'))).toBe(false);
    expect(sameNoopToken(undefined, tok('1:1', 'x'))).toBe(false);
  });
});

describe('NoopMemoDiag: per type outcomes for the diagnosis', () => {
  it('should report each hit check outcome once per intent, with its distinct keys per type', async () => {
    const memo = new NoopMemo(100);
    const key = noopMemoKey(intentOf({})) as string;
    memo.record(recordOf(key, basisOf('i1', 'external-reference--1')));
    const diag = new NoopMemoDiag();
    const batch = [
      intentOf({}), // hit
      intentOf({}), // hit, same key
      intentOf({ input: { source_name: 'other' }, candidateIds: ['external-reference--2'] }), // no entry
      intentOf({ opts: { references: ['x'] }, candidateIds: ['external-reference--3'] }), // ineligible
    ];
    await takeNoopMemoHits(batch, memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set(['External-Reference']), (intent, outcome, k) => diag.count(intent.type, outcome, k));
    diag.count('External-Reference', 'recorded', key);
    expect(diag.summary()).toEqual({ 'External-Reference': { distinct_keys: 2, hit: 2, no_entry: 1, ineligible: 1, recorded: 1 } });
  });
});

describe('identity map basis served to the upsert', () => {
  const savedMode = SEQUENCER_CONFIG.mode;
  const savedTtl = SEQUENCER_CONFIG.identityMapTtlS;
  beforeAll(() => {
    SEQUENCER_CONFIG.mode = 'batch';
    SEQUENCER_CONFIG.identityMapTtlS = 600;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.mode = savedMode;
    SEQUENCER_CONFIG.identityMapTtlS = savedTtl;
  });
  const bypassUser = { id: 'user1', internal_id: 'user1', capabilities: [{ name: 'BYPASS' }], origin: {} } as unknown as AuthUser;

  it('should be the very object serveWithRefs hands the upsert', async () => {
    const map = new SequencerIdentityMap();
    const basis = basisOf('i1', 'external-reference--1');
    map.ingestWithRefs(basis);
    const served = await map.serveWithRefs(executionContext('test'), bypassUser, ['external-reference--1'], {});
    expect(served?.hits[0]).toBe(basis);
    expect(map.withRefsBasisOf('external-reference--1')).toBe(basis);
    expect(map.withRefsBasisOf('i1')).toBe(basis);
  });

  it('should be absent for a bare entry, gone after an eviction, another object after a re-read', () => {
    const map = new SequencerIdentityMap();
    map.ingestBare([basisOf('i1', 'external-reference--1')]);
    expect(map.withRefsBasisOf('i1')).toBeNull();
    const basis = basisOf('i1', 'external-reference--1');
    map.ingestWithRefs(basis);
    map.evict(['external-reference--1']);
    expect(map.withRefsBasisOf('i1')).toBeNull();
    map.ingestWithRefs(basisOf('i1', 'external-reference--1'));
    expect(map.withRefsBasisOf('i1')).not.toBe(basis);
  });

  it('should expire with the entry', () => {
    const map = new SequencerIdentityMap();
    SEQUENCER_CONFIG.identityMapTtlS = -1;
    map.ingestWithRefs(basisOf('i1', 'external-reference--1'));
    SEQUENCER_CONFIG.identityMapTtlS = 600;
    expect(map.withRefsBasisOf('i1')).toBeNull();
  });
});

describe('isNoopOfServedBasis: a no-op counts only against the basis the map serves', () => {
  it('should give the basis when the apply compared with that very object', () => {
    const basis = basisOf('i1', 'external-reference--1');
    expect(isNoopOfServedBasis(new Map([['i1', basis]]), 'i1', () => basis)).toBe(basis);
  });

  it('should refuse an equal copy (loaded outside the map, or after a merge re-read), an evicted basis, another id', () => {
    const basis = basisOf('i1', 'external-reference--1');
    const copy = basisOf('i1', 'external-reference--1');
    expect(isNoopOfServedBasis(new Map([['i1', copy]]), 'i1', () => basis)).toBeNull();
    expect(isNoopOfServedBasis(new Map([['i1', basis]]), 'i1', () => null)).toBeNull();
    expect(isNoopOfServedBasis(new Map([['i2', basis]]), 'i1', () => basis)).toBeNull();
    expect(isNoopOfServedBasis(new Map(), 'i1', () => basis)).toBeNull();
  });
});

describe('no-op sink on the applying context', () => {
  it('should reach spread copies and re-scoped applying contexts, never a bypass scope', () => {
    const sink = new Map<string, object>();
    const applying = sequencerScopedContext({ source: 'test' } as unknown as AuthContext, 'applying', [], sink);
    const copy = { ...applying, user: undefined } as AuthContext;
    expect(copy.sequencer?.noopSink).toBe(sink);
    expect(sequencerScopedContext(copy, 'applying').sequencer?.noopSink).toBe(sink);
    expect(sequencerScopedContext(copy, 'applying', []).sequencer?.noopSink).toBe(sink);
    expect(sequencerScopedContext(copy, 'bypass').sequencer?.noopSink).toBeUndefined();
  });
});
