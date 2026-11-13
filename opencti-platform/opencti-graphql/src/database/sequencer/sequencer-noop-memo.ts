// POC ingestion sequencer (task 0040, 2026-11-10): memo of the entity upserts that changed nothing.
// pycti sends one create per embedded sub-object occurrence (an author or a marking is upserted
// with every object it is attached to, 97% of the upserts of mix285k change nothing). An upsert
// result is a function of its input, its user and its diff basis: once an apply ended as a no-op
// against a basis, the same input of the same user against the same stored document is that no-op
// again. Such an intent is settled at the batch start with the recorded result: no resolution,
// plan, lock key nor apply.
// Validity token (2026-11-13): the stored document's version (_seq_no and _primary_term, read
// realtime) and a hash of its source without `refreshed_at` and the denormalized `rel_*` fields.
// The token holds when either is unchanged. The version changes on every write, from any platform,
// including a ref appended by an entity citing the document (impacted roles: external references,
// sectors...), which sets only `rel_*` and `refreshed_at` and cannot change an upsert's outcome. The
// hash ignores exactly those: every attribute stays covered, and a removal of one of the
// document's own refs also sets its `updated_at` (cleanup script, from side). Ingestion only adds
// refs, and an input whose refs are already all there stays a no-op after more are added.
// The identity of the map's basis object was the first token: it never hit, the batch re-reads
// every upsert basis. The token is read before the basis and again at commit, and a no-op is
// recorded only when both match: the basis it was compared with is then exactly that document.
// Eligible intents only: entity creates without opts but `complete` (part of the key: the result
// shape depends on it; markings are created with it), outside a
// draft (the map never serves a draft), without a replay context (eventId, synchronizedUpsert:
// their freshness checks read more than the basis), whose input is plain data without data URIs
// (files and embedded images have side effects even when the patch is empty).
import { createHash } from 'node:crypto';
import { getInstanceIds } from '../../schema/identifier';
import { getDraftContext } from '../../utils/draftContext';
import type { SequencerIntent } from './sequencer-intent';

// A stored document: `${_seq_no}:${_primary_term}` and the hash of its source without `rel_*` and
// `refreshed_at` (NOOP_TOKEN_SOURCE_EXCLUDES)
export interface NoopToken {
  version: string;
  hash: string;
}
export const NOOP_TOKEN_SOURCE_EXCLUDES = ['rel_*', 'refreshed_at'];
export interface NoopTarget {
  id: string; // internal id, the document id
  index: string;
}
// The current tokens of the targets by internal id, a target not found is absent
export type NoopVersionsOf = (targets: NoopTarget[]) => Promise<Map<string, NoopToken>>;

export interface NoopMemoEntry {
  result: any;
  targetId: string;
  targetIndex: string;
  targetIds: string[];
  token: NoopToken;
}

// A no-op seen at apply, recorded at commit if its target kept the token read before its basis
export interface NoopRecord extends NoopMemoEntry {
  key: string;
}

// The canonical text of a plain input, null when it is not plain data (a file, a promise, a class
// instance) or carries a data URI (rewriteEmbeddedDataUriImagesInDescriptions uploads it)
const canonicalInput = (value: unknown): string | null => {
  if (value === null || value === undefined) return value === null ? 'null' : 'u';
  if (typeof value === 'string') return value.includes('data:') ? null : JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : `d${value.toISOString()}`;
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let i = 0; i < value.length; i += 1) {
      const item = canonicalInput(value[i]);
      if (item === null) return null;
      items.push(item);
    }
    return `[${items.join(',')}]`;
  }
  // GraphQL input objects have a null prototype (graphql-js), a mutation's input is one
  if (typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    const keys = Object.keys(value).sort();
    const fields: string[] = [];
    for (let i = 0; i < keys.length; i += 1) {
      const field = canonicalInput((value as Record<string, unknown>)[keys[i]]);
      if (field === null) return null;
      fields.push(`${JSON.stringify(keys[i])}:${field}`);
    }
    return `{${fields.join(',')}}`;
  }
  return null;
};

// JSON with sorted keys: the same source always hashes the same
const stableJson = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableJson((value as Record<string, unknown>)[k])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'u';
};

// The token of a document read with NOOP_TOKEN_SOURCE_EXCLUDES
export const noopTokenOf = (seqNo: number, primaryTerm: number, source: unknown): NoopToken => ({
  version: `${seqNo}:${primaryTerm}`,
  hash: createHash('sha1').update(stableJson(source ?? null)).digest('base64'),
});

// Same document for the memo: same version, or same source but `rel_*` and `refreshed_at`
export const sameNoopToken = (current: NoopToken | undefined, recorded: NoopToken): boolean => current !== undefined
  && (current.version === recorded.version || current.hash === recorded.hash);

// The memo key of an intent, null when it is not eligible
export const noopMemoKey = (intent: SequencerIntent): string | null => {
  if (intent.kind !== 'entity') return null;
  const optKeys = Object.keys(intent.opts ?? {});
  if (optKeys.some((k) => k !== 'complete')) return null;
  const complete = intent.opts?.complete === true;
  if (intent.context?.eventId || intent.context?.synchronizedUpsert) return null;
  if (getDraftContext(intent.context, intent.user)) return null;
  const input = canonicalInput(intent.input);
  return input === null ? null : `${intent.user.id}|${intent.type}|${complete ? 'c' : ''}|${input}`;
};

// The record of a no-op apply against `basis`, null without a token read before the basis. A
// complete result carries the element under `element`.
export const noopRecordOf = (key: string, basis: any, result: any, token: NoopToken | undefined): NoopRecord | null => {
  const targetId = (result?.element ?? result)?.internal_id;
  if (token === undefined || typeof targetId !== 'string' || targetId !== basis?.internal_id || typeof basis._index !== 'string') return null;
  return { key, result, targetId, targetIndex: basis._index, targetIds: getInstanceIds(basis), token };
};

// LRU bounded
export class NoopMemo {
  private entries = new Map<string, NoopMemoEntry>();

  constructor(private readonly maxSize: number) {}

  size() {
    return this.entries.size;
  }

  get(key: string): NoopMemoEntry | undefined {
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      this.entries.set(key, entry);
    }
    return entry;
  }

  record({ key, ...entry }: NoopRecord) {
    this.entries.delete(key);
    this.entries.set(key, entry);
    while (this.entries.size > this.maxSize) {
      this.entries.delete(this.entries.keys().next().value as string);
    }
  }

  delete(key: string) {
    this.entries.delete(key);
  }
}

const distinctTargets = (entries: NoopMemoEntry[]): NoopTarget[] => {
  const targets = new Map<string, NoopTarget>();
  entries.forEach((entry) => targets.set(entry.targetId, { id: entry.targetId, index: entry.targetIndex }));
  return Array.from(targets.values());
};

// Commit of a batch: the no-ops whose target this batch wrote are dropped (the record's token
// predates that write), the others are kept when the target still has the token read before their
// basis, all read in one go (hashMatches: kept on the source hash, the version had moved)
export const settleNoopRecords = async (
  records: NoopRecord[],
  writtenIds: Iterable<string>,
  versionsOf: NoopVersionsOf,
): Promise<{ kept: NoopRecord[]; dropped: number; hashMatches: number }> => {
  if (records.length === 0) return { kept: [], dropped: 0, hashMatches: 0 };
  const written = new Set(writtenIds);
  const unwritten = records.filter((record) => !record.targetIds.some((id) => written.has(id)));
  const tokens = unwritten.length > 0 ? await versionsOf(distinctTargets(unwritten)) : new Map<string, NoopToken>();
  const kept = unwritten.filter((record) => sameNoopToken(tokens.get(record.targetId), record.token));
  const hashMatches = kept.filter((record) => tokens.get(record.targetId)?.version !== record.token.version).length;
  return { kept, dropped: records.length - kept.length, hashMatches };
};

export interface NoopMemoHit {
  intent: SequencerIntent;
  result: any;
}

export interface NoopMemoMisses {
  ineligible: number;
  noEntry: number;
  tokenChanged: number;
  inBatchWriter: number;
  hashMatches: number; // not a miss: candidates kept on the source hash, the version had moved
}

// The intents of a batch the memo settles, the others in their batch order. An intent is a hit
// when its target still has the recorded version (read now, one round trip for the batch), and no
// other entity intent of the batch may write the target (one of its candidate ids is an id of the
// target): it would apply before or after, and the recorded result only holds against that
// version. Two hits on one target are both no-ops of the same version, in any order. A changed
// version never comes back: its entry is deleted. The key of every eligible intent of a keyed
// type is kept in `keys`, computed before any plan-time strip mutates the input; a type joins
// `keyedTypes` at its first no-op apply (that one is not recorded).
export const takeNoopMemoHits = async (
  batch: SequencerIntent[],
  memo: NoopMemo,
  versionsOf: NoopVersionsOf,
  keys: WeakMap<SequencerIntent, string>,
  keyedTypes: Set<string>,
  onOutcome?: (intent: SequencerIntent, outcome: NoopDiagOutcome, key: string | null) => void,
): Promise<{ hits: NoopMemoHit[]; rest: SequencerIntent[]; misses: NoopMemoMisses }> => {
  const misses: NoopMemoMisses = { ineligible: 0, noEntry: 0, tokenChanged: 0, inBatchWriter: 0, hashMatches: 0 };
  const candidates = new Map<SequencerIntent, { key: string; entry: NoopMemoEntry }>();
  batch.forEach((intent) => {
    // a key costs a walk of the input: only for the types an apply already ended as a no-op
    if (!keyedTypes.has(intent.type)) return;
    const key = noopMemoKey(intent);
    if (key === null) {
      misses.ineligible += 1;
      onOutcome?.(intent, 'ineligible', null);
      return;
    }
    keys.set(intent, key);
    const entry = memo.get(key);
    if (entry) {
      candidates.set(intent, { key, entry });
    } else {
      misses.noEntry += 1;
      onOutcome?.(intent, 'no_entry', key);
    }
  });
  if (candidates.size === 0) return { hits: [], rest: batch, misses };
  const tokens = await versionsOf(distinctTargets(Array.from(candidates.values()).map(({ entry }) => entry)));
  candidates.forEach(({ key, entry }, intent) => {
    const current = tokens.get(entry.targetId);
    if (current !== undefined && current.version !== entry.token.version && current.hash === entry.token.hash) misses.hashMatches += 1;
    if (!sameNoopToken(current, entry.token)) {
      memo.delete(key);
      candidates.delete(intent);
      misses.tokenChanged += 1;
      onOutcome?.(intent, 'token_changed', key);
    }
  });
  const writerIds = new Set<string>();
  batch.forEach((intent) => {
    if (intent.kind === 'entity' && !candidates.has(intent)) intent.candidateIds.forEach((id) => writerIds.add(id));
  });
  const hits: NoopMemoHit[] = [];
  const rest: SequencerIntent[] = [];
  batch.forEach((intent) => {
    const candidate = candidates.get(intent);
    if (!candidate) {
      rest.push(intent);
    } else if (candidate.entry.targetIds.some((id) => writerIds.has(id))) {
      misses.inBatchWriter += 1;
      onOutcome?.(intent, 'inbatch_writer', candidate.key);
      rest.push(intent);
    } else {
      onOutcome?.(intent, 'hit', candidate.key);
      hits.push({ intent, result: candidate.entry.result });
    }
  });
  return { hits, rest, misses };
};

// task 0040 diagnosis (contention_diag): per entity type, what happened to the memo's intents and how
// many distinct keys they carry. Distinct keys close to the intent count means inputs that vary per
// occurrence (nothing to memoize); far below it with many no_entry means records that do not land.
export type NoopDiagOutcome = 'ineligible' | 'no_entry' | 'token_changed' | 'inbatch_writer' | 'hit'
  | 'applied_noop' | 'applied_write' | 'applied_create' | 'recorded' | 'dropped_written' | 'dropped_version';

// FNV-1a: the diagnosis counts distinct keys without holding them
const keyHash = (key: string): number => {
  let hash = 0x811c9dc5;
  for (let i = 0; i < key.length; i += 1) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
};

export class NoopMemoDiag {
  private types = new Map<string, { keys: Set<number>; counts: Partial<Record<NoopDiagOutcome, number>> }>();

  count(type: string, outcome: NoopDiagOutcome, key: string | null = null) {
    let stats = this.types.get(type);
    if (!stats) {
      stats = { keys: new Set(), counts: {} };
      this.types.set(type, stats);
    }
    stats.counts[outcome] = (stats.counts[outcome] ?? 0) + 1;
    if (key !== null) stats.keys.add(keyHash(key));
  }

  summary(): Record<string, Partial<Record<NoopDiagOutcome | 'distinct_keys', number>>> {
    const out: Record<string, Partial<Record<NoopDiagOutcome | 'distinct_keys', number>>> = {};
    this.types.forEach(({ keys, counts }, type) => {
      out[type] = { distinct_keys: keys.size, ...counts };
    });
    return out;
  }
}

// An apply's upsert of `internalId` changed nothing against the basis the identity map serves:
// the element it compared with IS that basis. A merge before the upsert evicts the target, a basis
// loaded outside the map is another object: neither is a no-op of the map's basis.
export const isNoopOfServedBasis = (noopSink: Map<string, object>, internalId: string, basisOf: (id: string) => object | null): object | null => {
  const compared = noopSink.get(internalId);
  if (!compared) return null; // most applies: spares the map lookup
  const basis = basisOf(internalId);
  return basis === compared ? basis : null;
};
