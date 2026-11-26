import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import moment from 'moment/moment';
import '../../../src/modules/index';
import {
  isLikelyNoop,
  isNoopOfServedBasis,
  noopDateMs,
  noopDatesHold,
  noopKeyDateFields,
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
import { buildUpdatePatchForUpsert } from '../../../src/utils/upsert-utils';
import { generateStandardId, getInputIds } from '../../../src/schema/identifier';
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
    const first = noopMemoKey(intentOf({ input: { first_seen: new Date('2024-01-01T00:00:00.000Z') } }));
    const second = noopMemoKey(intentOf({ input: { first_seen: new Date('2025-01-01T00:00:00.000Z') } }));
    expect(first).not.toBeNull();
    expect(first).not.toEqual(second);
    expect(noopMemoKey(intentOf({ input: { first_seen: new Date('invalid') } }))).toBeNull();
  });

  it('should leave created and modified out of the key (connectors re-stamp them per bundle), unreadable ones refused', () => {
    const sector = (input: Record<string, any>) => noopMemoKey(intentOf({ type: 'Sector', input: { name: 'Technology', ...input } }));
    const plain = sector({});
    expect(plain).not.toBeNull();
    expect(sector({ created: '2026-11-03T09:51:00.218Z', modified: new Date('2026-11-03T09:51:00.218Z') })).toEqual(plain);
    expect(sector({ created: '2026-11-03T09:51:03.608Z', modified: '2026-11-03T09:51:03.608Z' })).toEqual(plain);
    expect(sector({ created: 'not a date' })).toBeNull();
    expect(sector({ modified: new Date('invalid') })).toBeNull();
  });

  it('should leave out only the dates the upsert merely aligns: those of a standard id, a completion or no attribute stay', () => {
    // created makes the standard id (another date is another entity), or the indicator validity derives from it
    expect(noopKeyDateFields('Sector')).toEqual(['created', 'modified']);
    ['Country', 'Malware', 'Intrusion-Set', 'Organization', 'Attack-Pattern'].forEach((type) => expect(noopKeyDateFields(type)).toEqual(['created', 'modified']));
    ['Incident', 'Note', 'Opinion', 'Grouping', 'Case-Incident', 'Task', 'Feedback', 'Case-Rft', 'Case-Rfi', 'Indicator', 'StixFile', 'IPv4-Addr']
      .forEach((type) => expect(noopKeyDateFields(type)).not.toContain('created'));
    expect(noopKeyDateFields('Indicator')).toEqual([]);
    expect(noopKeyDateFields('IPv4-Addr')).toEqual([]);
    expect(noopKeyDateFields('Not-A-Type')).toEqual([]);
  });

  it('should key a re-dated incident, note, indicator or observable apart, a re-dated malware together', () => {
    const keyOf = (type: string, created: string) => noopMemoKey(intentOf({ type, input: { name: 'n', pattern: 'p', content: 'c', value: '1.2.3.4', created } }));
    ['Incident', 'Note', 'Indicator', 'IPv4-Addr'].forEach((type) => {
      expect(keyOf(type, '2026-11-03T09:51:00.218Z')).not.toBeNull();
      expect(keyOf(type, '2026-11-03T09:51:00.218Z')).not.toEqual(keyOf(type, '2026-11-03T09:51:03.608Z'));
    });
    expect(keyOf('Malware', '2026-11-03T09:51:00.218Z')).toEqual(keyOf('Malware', '2026-11-03T09:51:03.608Z'));
    // a date that stays in the key is not read as a date: no refusal
    expect(keyOf('IPv4-Addr', 'not a date')).not.toBeNull();
  });

  it('should leave out only the top-level dates: a nested created stays in the key', () => {
    const inList = (created: string) => noopMemoKey(intentOf({ type: 'Sector', input: { name: 'Technology', externalReferences: [{ url: 'u', created }] } }));
    const inObject = (created: string) => noopMemoKey(intentOf({ type: 'Sector', input: { name: 'Technology', createdBy: { name: 'author', created } } }));
    [inList, inObject].forEach((keyOf) => {
      expect(keyOf('2026-11-03T09:51:00.218Z')).not.toBeNull();
      expect(keyOf('2026-11-03T09:51:00.218Z')).not.toEqual(keyOf('2026-11-03T09:51:03.608Z'));
    });
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
    // the direct path also resolves by the previous standard id: not in the key nor in the candidate ids
    expect(noopMemoKey(intentOf({ context: { previousStandard: 'external-reference--old' } }))).toBeNull();
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
// the no-op of `intent` (by default the External-Reference of intentOf) against `basis`
const recordOf = (key: string, basis: Record<string, any>, version = '7:1', intent = intentOf({})) => noopRecordOf(key, intent, { _index: 'idx', ...basis }, { _index: 'idx', ...basis }, tok(version)) as NoopRecord;

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
    const record = noopRecordOf('k', intentOf({}), basis, basis, tok('7:1'));
    expect(record).toMatchObject({ key: 'k', targetId: 'i1', targetIndex: 'idx', token: tok('7:1'), result: basis });
    expect(record?.targetIds).toEqual(expect.arrayContaining(['i1', 'external-reference--1', 'external-reference--old']));
  });

  it('should refuse a basis without a version read before it, a result of another element, a basis without index', () => {
    const basis = { _index: 'idx', ...basisOf('i1', 'external-reference--1') };
    expect(noopRecordOf('k', intentOf({}), basis, basis, undefined)).toBeNull();
    expect(noopRecordOf('k', intentOf({}), basis, { ...basis, internal_id: 'i2' }, tok('7:1'))).toBeNull();
    expect(noopRecordOf('k', intentOf({}), basisOf('i1', 'external-reference--1'), basisOf('i1', 'external-reference--1'), tok('7:1'))).toBeNull();
  });

  it('should read the target of a complete result under its element', () => {
    const basis = { _index: 'idx', ...basisOf('i1', 'marking-definition--1') };
    const complete = { element: basis, isCreation: false, event: null };
    expect(noopRecordOf('k', intentOf({}), basis, complete, tok('7:1'))).toMatchObject({ targetId: 'i1', result: complete });
  });

  it('should carry the target dates of the basis, null when empty or unreadable', () => {
    const basis = { _index: 'idx', ...basisOf('i1', 'identity--1', { created: '2020-01-23T00:00:00.000Z', modified: '' }) };
    expect(noopRecordOf('k', intentOf({}), basis, basis, tok('7:1'))?.targetDates).toEqual({ created: Date.parse('2020-01-23T00:00:00.000Z'), modified: null });
    const unreadable = { _index: 'idx', ...basisOf('i1', 'identity--1', { created: 'garbage' }) };
    expect(noopRecordOf('k', intentOf({}), unreadable, unreadable, tok('7:1'))?.targetDates).toEqual({ created: null, modified: null });
  });
});

describe('noopDatesHold: the input dates cannot change the target', () => {
  const dates = { created: Date.parse('2020-01-23T00:00:00.000Z'), modified: Date.parse('2020-02-01T00:00:00.000Z') };
  it('should hold without dates, for a created no older than the target one, for any modified when the target has one', () => {
    expect(noopDatesHold({ name: 'x' }, dates)).toBe(true);
    expect(noopDatesHold({ created: '2020-01-23T00:00:00.000Z' }, dates)).toBe(true);
    expect(noopDatesHold({ created: new Date('2026-11-03T09:51:00.000Z'), modified: '2026-11-03T09:51:00.000Z' }, dates)).toBe(true);
    expect(noopDatesHold({ modified: '2019-01-01T00:00:00.000Z' }, dates)).toBe(true);
  });

  it('should not hold for an older created (the upsert keeps it), a date on a target without one, an unreadable date', () => {
    expect(noopDatesHold({ created: '2019-12-31T23:59:59.999Z' }, dates)).toBe(false);
    expect(noopDatesHold({ created: '2026-11-03T09:51:00.000Z' }, { ...dates, created: null })).toBe(false);
    expect(noopDatesHold({ modified: '2026-11-03T09:51:00.000Z' }, { ...dates, modified: null })).toBe(false);
    expect(noopDatesHold({ created: 'not a date' }, dates)).toBe(false);
  });

  it('should read empty dates as absent, on a target without dates too, and check only the fields left out of the key', () => {
    const none = { created: null, modified: null };
    expect(noopDatesHold({ name: 'x' }, none)).toBe(true);
    expect(noopDatesHold({ created: '', modified: '' }, none)).toBe(true);
    expect(noopDatesHold({ created: null }, none)).toBe(true);
    expect(noopDatesHold({ created: '2026-11-03T09:51:00.000Z' }, none)).toBe(false);
    // created kept in the key: the record already compared that very date
    expect(noopDatesHold({ created: '2019-12-31T23:59:59.999Z' }, dates, ['modified'])).toBe(true);
    expect(noopDatesHold({ created: '2026-11-03T09:51:00.000Z', modified: '2026-11-03T09:51:00.000Z' }, none, [])).toBe(true);
  });
});

describe('noopDatesHold reads a date as the upsert does (moment, local time without a zone)', () => {
  const tz = process.env.TZ;
  beforeAll(() => {
    process.env.TZ = 'Europe/Paris';
  });
  afterAll(() => {
    if (tz === undefined) delete process.env.TZ;
    else process.env.TZ = tz;
  });
  it('should hold exactly when the upsert keeps the stored created', () => {
    const stored = '2020-01-23T00:00:00.000Z';
    const user = { id: 'u1' } as unknown as AuthUser;
    const keeps = (created: string) => buildUpdatePatchForUpsert(user, { created: stored }, 'Sector', { created }, { isConfidenceMatch: true, confidenceLevelToApply: 100 }).created === stored;
    const inputs = ['2020-01-23', '2020-01-24', '2020-01-23T00:00:00', '2020-01-23T00:30:00', '2020-01-23T00:00:00.000Z', '2020-01-22T23:59:59.999Z',
      '2020-01-23T01:00:00+01:00', '2020-01-23T00:59:59+01:00', '2020-01-23T00:00:00.001Z', '2021-06-01T12:00:00+02:00'];
    // a date without a zone is local time: '2020-01-23' is 2020-01-22T23:00Z in Paris, older than the stored one
    expect(keeps('2020-01-23')).toBe(false);
    inputs.forEach((created) => {
      expect(noopDatesHold({ created }, { created: Date.parse(stored), modified: null }, ['created']), created).toEqual(keeps(created));
    });
  });
});

describe('noopDateMs reads every string as moment does', () => {
  // a deterministic grid: leap and non-leap years (0100, 1900, 2100 are not), impossible months and days, hour
  // 24, minute and second 60, fractions of 1 to 4 digits; the other shapes (no zone, offsets, z) go to moment
  const pad = (n: number) => String(n).padStart(2, '0');
  const dates = ['0000', '0004', '0050', '0100', '1900', '2000', '2020', '2021', '2100', '9999']
    .flatMap((year) => Array.from({ length: 14 }, (_, month) => Array.from({ length: 33 }, (__, day) => `${year}-${pad(month)}-${pad(day)}`)).flat());
  const utcTimes = ['00:00:00', '23:59:59.999', '24:00:00', '24:00:00.000', '12:00:60', '12:60:00', '25:00:00', '12:00:00.5', '12:00:00.05', '12:00:00.1234'];
  const otherShapes = ['', 'T12:00Z', 'T12:00:00', 'T12:00:00z', 'T12:00:00+00:00', 'T12:00:00+14:30'];
  const utcGrid = dates.flatMap((date) => utcTimes.map((time) => `${date}T${time}Z`));
  const grid = [...utcGrid, ...dates.flatMap((date) => otherShapes.map((shape) => `${date}${shape}`))];
  const tz = process.env.TZ;
  beforeAll(() => {
    process.env.TZ = 'Europe/Paris';
  });
  afterAll(() => {
    if (tz === undefined) delete process.env.TZ;
    else process.env.TZ = tz;
  });
  it('should give the instant moment gives, NaN when moment rejects the date', () => {
    // the UTC instants (the fast path's shape) hold impossible days Date.parse rolls over where moment refuses
    // them (2021-02-29 read as March 1st): 396 on this grid
    expect(utcGrid.filter((value) => !Number.isNaN(Date.parse(value)) && Number.isNaN(moment(value).valueOf())).length).toBeGreaterThan(300);
    grid.forEach((value) => expect(noopDateMs(value), value).toEqual(moment(value).valueOf()));
  });
  it('should keep an intent with a date moment rejects out of the memo', () => {
    expect(noopMemoKey(intentOf({ type: 'Sector', input: { name: 'S', created: '2021-02-29T00:00:00Z' } }))).toBeNull();
    expect(noopMemoKey(intentOf({ type: 'Sector', input: { name: 'S', created: '2021-03-01T00:00:00Z' } }))).not.toBeNull();
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

describe('isLikelyNoop: the hint follows the dates and ids the batch check reads', () => {
  const sector = (created: string, candidateIds = ['identity--1']) => intentOf({ type: 'Sector', input: { name: 'Technology', created }, candidateIds });
  const memoOf = () => {
    const memo = new NoopMemo(100);
    memo.record(recordOf(noopMemoKey(sector('2026-11-03T09:51:00.218Z')) as string, basisOf('i1', 'identity--1', { created: '2026-11-03T09:51:00.218Z' })));
    return memo;
  };
  it('should tag a re-stamped repeat, not one whose older created or other id the batch check refuses', () => {
    const types = new Set(['Sector']);
    expect(isLikelyNoop(sector('2026-11-03T09:51:03.608Z'), memoOf(), types)).toBe(true);
    expect(isLikelyNoop(sector('2025-12-29T19:37:08.000Z'), memoOf(), types)).toBe(false);
    expect(isLikelyNoop(sector('2026-11-03T09:51:03.608Z', ['identity--2']), memoOf(), types)).toBe(false);
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

  it('should settle a re-stamped repeat whose dates cannot change the target, and keep the entry for one that can', async () => {
    const memo = new NoopMemo(100);
    const sector = (created: string) => intentOf({ type: 'Sector', input: { name: 'Technology', created, modified: created }, candidateIds: ['identity--1'] });
    const key = noopMemoKey(sector('2026-11-03T09:51:00.218Z')) as string;
    memo.record(recordOf(key, basisOf('i1', 'identity--1', { created: '2026-11-03T09:51:00.218Z', modified: '2026-11-03T09:51:00.218Z' })));
    const { versionsOf } = versionsServer({ i1: '7:1' });
    const restamped = sector('2026-11-03T09:51:03.608Z');
    const first = await takeNoopMemoHits([restamped], memo, versionsOf, new WeakMap(), new Set(['Sector']));
    expect(first.hits.map((h) => h.intent)).toEqual([restamped]);
    const older = sector('2025-12-29T19:37:08.000Z');
    const second = await takeNoopMemoHits([older], memo, versionsOf, new WeakMap(), new Set(['Sector']));
    expect(second.hits).toEqual([]);
    expect(second.rest).toEqual([older]);
    expect(second.misses.datesChanged).toEqual(1);
    expect(memo.get(key)).toBeDefined();
    // in one batch, the older one may write the target: the re-stamped repeat is not settled either
    const both = await takeNoopMemoHits([sector('2026-11-03T09:51:03.608Z'), sector('2025-12-29T19:37:08.000Z')], memo, versionsOf, new WeakMap(), new Set(['Sector']));
    expect(both.hits).toEqual([]);
    expect(both.misses.inBatchWriter).toEqual(1);
  });

  it('should not settle a dateless key repeat that resolves by an id the target lacks, and keep the entry', async () => {
    const memo = new NoopMemo(100);
    const sector = (candidateIds: string[], created = '2026-11-03T09:51:00.218Z') => intentOf({ type: 'Sector', input: { name: 'Technology', created }, candidateIds });
    const key = noopMemoKey(sector(['identity--1'])) as string;
    memo.record(recordOf(key, basisOf('i1', 'identity--1', { created: '2026-11-03T09:51:00.218Z' })));
    const { versionsOf } = versionsServer({ i1: '7:1' });
    const outcomes: string[] = [];
    const other = sector(['identity--2'], '2026-11-03T09:51:03.608Z');
    const unresolved = sector([], '2026-11-03T09:51:03.608Z');
    const { hits, rest, misses } = await takeNoopMemoHits([other, unresolved], memo, versionsOf, new WeakMap(), new Set(['Sector']), (_, outcome) => outcomes.push(outcome));
    expect(hits).toEqual([]);
    expect(rest).toEqual([other, unresolved]);
    expect(misses.idsChanged).toEqual(2);
    expect(outcomes).toEqual(['ids_changed', 'ids_changed']);
    expect(memo.get(key)).toBeDefined();
    const repeat = sector(['identity--1'], '2026-11-03T09:51:03.608Z');
    expect((await takeNoopMemoHits([repeat], memo, versionsOf, new WeakMap(), new Set(['Sector']))).hits.map((h) => h.intent)).toEqual([repeat]);
  });

  it('should settle an observable repeat carrying a date its target does not store (the date stays in the key)', async () => {
    const memo = new NoopMemo(100);
    const ip = () => intentOf({ type: 'IPv4-Addr', input: { value: '1.2.3.4', created: '2026-11-03T09:51:00.218Z' }, candidateIds: ['ipv4-addr--1'] });
    memo.record(recordOf(noopMemoKey(ip()) as string, basisOf('i1', 'ipv4-addr--1', { entity_type: 'IPv4-Addr' })));
    const repeat = ip();
    const { hits } = await takeNoopMemoHits([repeat], memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set(['IPv4-Addr']));
    expect(hits.map((h) => h.intent)).toEqual([repeat]);
  });

  it('should keep a different incident date apart: another key, never the recorded target', async () => {
    const memo = new NoopMemo(100);
    const incident = (created: string) => intentOf({ type: 'Incident', input: { name: 'Breach', created }, candidateIds: [`incident--${created}`] });
    memo.record(recordOf(noopMemoKey(incident('2026-11-03T09:51:00.218Z')) as string, basisOf('i1', 'incident--2026-11-03T09:51:00.218Z', { created: '2026-11-03T09:51:00.218Z' })));
    const later = incident('2026-11-04T00:00:00.000Z');
    const { hits, misses } = await takeNoopMemoHits([later], memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set(['Incident']));
    expect(hits).toEqual([]);
    expect(misses.noEntry).toEqual(1);
  });

  it('should key a dates_changed intent and report it once in the diagnosis', async () => {
    const memo = new NoopMemo(100);
    const sector = (created: string) => intentOf({ type: 'Sector', input: { name: 'Technology', created }, candidateIds: ['identity--1'] });
    const key = noopMemoKey(sector('2026-11-03T09:51:00.218Z')) as string;
    memo.record(recordOf(key, basisOf('i1', 'identity--1', { created: '2026-11-03T09:51:00.218Z' })));
    const older = sector('2025-12-29T19:37:08.000Z');
    const keys = new WeakMap<any, string>();
    const diag = new NoopMemoDiag();
    await takeNoopMemoHits([older], memo, versionsServer({ i1: '7:1' }).versionsOf, keys, new Set(['Sector']), (intent, outcome, k) => diag.count(intent.type, outcome, k));
    expect(keys.get(older)).toEqual(key);
    expect(diag.summary()).toEqual({ Sector: { distinct_keys: 1, dates_changed: 1 } });
  });

  it('should settle the exact repeat of a recorded no-op whose dates or ids the rules alone refuse (lower confidence, stix id)', async () => {
    const memo = new NoopMemo(100);
    // an older created the upsert ignored (confidence below the target's), resolved by a stix id beside an id the target lacks
    const sector = (created: string, candidateIds = ['identity--stix', 'identity--generated']) => intentOf({ type: 'Sector', input: { name: 'Technology', stix_id: 'identity--stix', created }, candidateIds });
    const recorder = sector('2019-01-01T00:00:00.000Z');
    const key = noopMemoKey(recorder) as string;
    memo.record(recordOf(key, basisOf('i1', 'identity--1', { created: '2020-01-23T00:00:00.000Z', x_opencti_stix_ids: ['identity--stix'] }), '7:1', recorder));
    const { versionsOf } = versionsServer({ i1: '7:1' });
    const repeat = sector('2019-01-01T00:00:00.000Z');
    expect((await takeNoopMemoHits([repeat], memo, versionsOf, new WeakMap(), new Set(['Sector']))).hits.map((h) => h.intent)).toEqual([repeat]);
    const otherDate = await takeNoopMemoHits([sector('2018-01-01T00:00:00.000Z')], memo, versionsOf, new WeakMap(), new Set(['Sector']));
    expect(otherDate.misses.datesChanged).toEqual(1);
    const otherIds = await takeNoopMemoHits([sector('2019-01-01T00:00:00.000Z', ['identity--stix', 'identity--elsewhere'])], memo, versionsOf, new WeakMap(), new Set(['Sector']));
    expect(otherIds.misses.idsChanged).toEqual(1);
  });

  it('should refuse a partial id overlap, and let it block a same-target repeat of the batch', async () => {
    const memo = new NoopMemo(100);
    const sector = (candidateIds: string[], created = '2026-11-03T09:51:03.608Z') => intentOf({ type: 'Sector', input: { name: 'Technology', created }, candidateIds });
    const recorder = sector(['identity--1'], '2026-11-03T09:51:00.218Z');
    memo.record(recordOf(noopMemoKey(recorder) as string, basisOf('i1', 'identity--1', { created: '2026-11-03T09:51:00.218Z' }), '7:1', recorder));
    const partial = sector(['identity--1', 'identity--2']);
    const repeat = sector(['identity--1']);
    const { hits, misses } = await takeNoopMemoHits([partial, repeat], memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set(['Sector']));
    expect(hits).toEqual([]);
    expect(misses.idsChanged).toEqual(1);
    expect(misses.inBatchWriter).toEqual(1);
  });

  it('should refuse ids that are only part of the recorded ones, or the same ones repeated, when some are not the target\'s', async () => {
    const memo = new NoopMemo(100);
    const sector = (candidateIds: string[]) => intentOf({ type: 'Sector', input: { name: 'Technology', created: '2026-11-03T09:51:00.218Z' }, candidateIds });
    const recorder = sector(['identity--1', 'identity--elsewhere']);
    memo.record(recordOf(noopMemoKey(recorder) as string, basisOf('i1', 'identity--1', { created: '2026-11-03T09:51:00.218Z' }), '7:1', recorder));
    const { versionsOf } = versionsServer({ i1: '7:1' });
    const subset = await takeNoopMemoHits([sector(['identity--elsewhere'])], memo, versionsOf, new WeakMap(), new Set(['Sector']));
    expect(subset.misses.idsChanged).toEqual(1);
    const repeated = await takeNoopMemoHits([sector(['identity--elsewhere', 'identity--elsewhere'])], memo, versionsOf, new WeakMap(), new Set(['Sector']));
    expect(repeated.misses.idsChanged).toEqual(1);
    const same = sector(['identity--elsewhere', 'identity--1', 'identity--1']);
    expect((await takeNoopMemoHits([same], memo, versionsOf, new WeakMap(), new Set(['Sector']))).hits.map((h) => h.intent)).toEqual([same]);
  });

  it('should not check the ids of a type that keeps its dates in the key', async () => {
    const memo = new NoopMemo(100);
    const ip = () => intentOf({ type: 'IPv4-Addr', input: { value: '1.2.3.4' }, candidateIds: ['ipv4-addr--hashed'] });
    memo.record(recordOf(noopMemoKey(ip()) as string, basisOf('i1', 'ipv4-addr--1', { entity_type: 'IPv4-Addr' }), '7:1', intentOf({ type: 'IPv4-Addr', candidateIds: ['ipv4-addr--other'] })));
    const repeat = ip();
    const { hits } = await takeNoopMemoHits([repeat], memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set(['IPv4-Addr']));
    expect(hits.map((h) => h.intent)).toEqual([repeat]);
  });

  it('should leave an entry where it is in the LRU on a miss: only a candidate refreshes it', async () => {
    const memo = new NoopMemo(2);
    const sector = (name: string, created = '2026-11-03T09:51:00.218Z') => intentOf({ type: 'Sector', input: { name, created }, candidateIds: [`identity--${name}`] });
    memo.record(recordOf(noopMemoKey(sector('a')) as string, basisOf('i1', 'identity--a', { created: '2026-11-03T09:51:00.218Z' }), '7:1', sector('a')));
    memo.record(recordOf(noopMemoKey(sector('b')) as string, basisOf('i2', 'identity--b', { created: '2026-11-03T09:51:00.218Z' }), '7:1', sector('b')));
    const { misses } = await takeNoopMemoHits([sector('a', '2025-01-01T00:00:00.000Z')], memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set(['Sector']));
    expect(misses.datesChanged).toEqual(1);
    memo.record(recordOf(noopMemoKey(sector('c')) as string, basisOf('i3', 'identity--c', { created: '2026-11-03T09:51:00.218Z' }), '7:1', sector('c')));
    expect(memo.peek(noopMemoKey(sector('a')) as string)).toBeUndefined();
    expect(memo.peek(noopMemoKey(sector('b')) as string)).toBeDefined();
    // a candidate moves its entry to the recent end: b, taken, survives the next record and c goes
    const candidate = await takeNoopMemoHits([sector('b')], memo, versionsServer({ i2: '7:1' }).versionsOf, new WeakMap(), new Set(['Sector']));
    expect(candidate.hits.map((h) => h.intent.input.name)).toEqual(['b']);
    memo.record(recordOf(noopMemoKey(sector('d')) as string, basisOf('i4', 'identity--d', { created: '2026-11-03T09:51:00.218Z' }), '7:1', sector('d')));
    expect(memo.peek(noopMemoKey(sector('b')) as string)).toBeDefined();
    expect(memo.peek(noopMemoKey(sector('c')) as string)).toBeUndefined();
  });

  it('should settle re-dated repeats with the ids the platform computes (stix id, aliases, name)', async () => {
    const cases: [string, Record<string, any>, Record<string, any>][] = [
      ['Sector', { name: 'Technology', stix_id: 'identity--0b5c66b1-0000-4000-8000-000000000001' }, { identity_class: 'class' }],
      ['Malware', { name: 'Anatsa', aliases: ['TeaBot', 'Toddler'] }, {}],
      ['Country', { name: 'France', x_opencti_location_type: 'Country' }, {}],
      ['Note', { content: 'note', created: '2026-11-03T09:51:00.218Z' }, {}],
    ];
    for (let i = 0; i < cases.length; i += 1) {
      const [type, input, extra] = cases[i];
      const intentAt = (stamp: string) => {
        const dated = { ...input, ...(type === 'Note' ? {} : { created: stamp }), modified: stamp };
        return intentOf({ type, input: dated, candidateIds: getInputIds(type, { ...dated, entity_type: type }, false) });
      };
      const recorder = intentAt('2026-11-03T09:51:00.218Z');
      const basis = basisOf('i1', generateStandardId(type, { ...input, entity_type: type }), {
        entity_type: type, ...extra, ...input, created: '2026-11-03T09:51:00.218Z', modified: '2026-11-03T09:51:00.218Z',
        x_opencti_stix_ids: input.stix_id ? [input.stix_id] : [],
      });
      const memo = new NoopMemo(100);
      memo.record(recordOf(noopMemoKey(recorder) as string, basis, '7:1', recorder));
      const repeat = intentAt('2026-11-04T10:00:00.000Z');
      const { hits, misses } = await takeNoopMemoHits([repeat], memo, versionsServer({ i1: '7:1' }).versionsOf, new WeakMap(), new Set([type]));
      expect({ type, hits: hits.length, misses }).toMatchObject({ type, hits: 1, misses: { idsChanged: 0, datesChanged: 0 } });
    }
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
