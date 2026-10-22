// Entry points for the scenarios: write inputs chunk by chunk with background settlers, settle everything, and the
// operations that stay on today's path (delete, rename) with their identity index updates.
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { deleteElementById, updateAttribute } from '../../../src/database/middleware';
import { elDeleteIndices, elRefreshIndices } from '../../../src/database/engine';
import { getClientBase } from '../../../src/database/redis';
import { REDIS_PREFIX } from '../../../src/config/conf';
import { READ_DATA_INDICES, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../../src/database/utils';
import { now as nowMs, phaseSummary, pool, resetPhases, round } from '../bench-utils';
import { IDENTITY_INDEX, identityKeys, setKeys } from '../../../src/database/lockfree/identity';
import { mgetRaw, toElements } from '../../../src/database/lockfree/load';
import { countPending, PENDING_INDEX } from '../../../src/database/lockfree/pending';
import { clearQueue, queueDepth } from '../../../src/database/lockfree/queue';
import { Settler, settlerCounters } from '../../../src/database/lockfree/settler';
import { add, type Counters, newCounters } from '../../../src/database/lockfree/store';
import type { WriteOptions } from '../../../src/database/lockfree/upsert';
import { type EntityItem, type ItemResult, writeEntityChunk, writeRelationChunk } from '../../../src/database/lockfree/writer';

// Users pending relationships are written as, by id
const knownUsers = new Map<string, AuthUser>([[ADMIN_USER.internal_id, ADMIN_USER]]);
export const registerUser = (user: AuthUser) => knownUsers.set(user.internal_id, user);

export const newSettler = (opts: { parallelBulks?: number; partitions?: number[]; consumer?: string; claimIdleMs?: number; pendingTtlMs?: number } = {}) => new Settler({
  ...opts,
  resolveUser: async (userId) => knownUsers.get(userId) ?? ADMIN_USER,
  writePending: async (context, user, inputs, counters) => {
    await writeRelationChunk(context, user, inputs, counters);
  },
});

export interface RunOptions extends WriteOptions {
  chunkSize: number; // objects per write call; 1 = one call per object, like one worker message
  concurrency: number; // calls in flight
  settleEveryMs: number; // settler period while writing
  settlers?: Settler[]; // the settlers to run (default: one owning every partition)
  settleParallel?: number; // update bulks a default settler sends at once
  noSettle?: boolean; // leave the settler work in the queue (to write more before it runs)
  user?: AuthUser;
  context?: AuthContext;
}

// Settle until the queue and the pending store are empty (or stop moving), then refresh
export const settleAll = async (settlers: Settler[], opts: { maxPasses?: number } = {}) => {
  for (let pass = 0; pass < (opts.maxPasses ?? 20); pass += 1) {
    const applied = await Promise.all(settlers.map((s) => s.flush()));
    const depth = await queueDepth();
    if (depth === 0 && applied.every((n) => n === 0)) break;
  }
  await elRefreshIndices([...READ_DATA_INDICES, ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED]);
};

const writeAll = async <T>(
  items: T[], opts: RunOptions,
  write: (context: AuthContext, user: AuthUser, chunk: T[], counters: Counters, opts: WriteOptions) => Promise<ItemResult[]>,
  sizeOf: (item: T) => number = () => 1,
) => {
  const counters = newCounters();
  const objects = items.reduce((n, item) => n + sizeOf(item), 0);
  const user = opts.user ?? ADMIN_USER;
  registerUser(user);
  const context = opts.context ?? testContext;
  const settlers = opts.settlers ?? [newSettler({ parallelBulks: opts.settleParallel })];
  const chunks = R.splitEvery(opts.chunkSize, items);
  const results: ItemResult[] = [];
  resetPhases();
  const startedAt = Date.now();
  const start = nowMs();
  let writing = !opts.noSettle;
  let stopWaiting = () => {};
  const stopped = new Promise<void>((resolve) => {
    stopWaiting = resolve;
  });
  const loops = settlers.map(async (settler) => {
    while (writing) {
      await Promise.race([new Promise((resolve) => {
        setTimeout(resolve, opts.settleEveryMs);
      }), stopped]);
      if (writing) await settler.flush();
    }
  });
  await pool(chunks, opts.concurrency, async (chunk) => {
    results.push(...await write(context, user, chunk, counters, { waitForSearch: opts.waitForSearch }));
  });
  const written = nowMs();
  writing = false;
  stopWaiting();
  await Promise.all(loops);
  if (!opts.noSettle) await settleAll(settlers);
  const settled = nowMs();
  const statuses = R.countBy((r: ItemResult) => r?.status ?? 'missing', results);
  const errors = R.countBy((r: ItemResult) => r.error ?? '', results.filter((r) => r?.status === 'error'));
  return {
    count: objects,
    chunk_size: opts.chunkSize,
    concurrency: opts.concurrency,
    settlers: settlers.length,
    write_ms: round(written - start),
    write_throughput_per_s: round((objects / (written - start)) * 1000),
    settle_after_write_ms: round(settled - written),
    settled_ms: round(settled - start),
    settled_throughput_per_s: round((objects / (settled - start)) * 1000),
    created: statuses.created ?? 0,
    merged: statuses.merged ?? 0,
    statuses,
    errors,
    writer: counters,
    settler: { ...settlerCounters(settlers), queue_left: await queueDepth(), pending_left: await countPending() },
    phases_ms: phaseSummary(),
    started_at: startedAt,
    ended_at: Date.now(),
    results,
  };
};

export const writeEntities = (items: EntityItem[], opts: RunOptions) => writeAll(items, opts, writeEntityChunk);
export const writeRelations = (inputs: Record<string, any>[], opts: RunOptions) => writeAll(inputs, opts, writeRelationChunk);

// A bundle as a connector sends it: its entities, then the relationships between them, in one chunk
export interface Bundle { entities: EntityItem[]; relations: Record<string, any>[] }
export const writeBundles = (bundles: Bundle[], opts: RunOptions) => writeAll(bundles, opts, async (context, user, chunk, counters, writeOpts) => {
  const out: ItemResult[] = [];
  for (const bundle of chunk) {
    out.push(...await writeEntityChunk(context, user, bundle.entities, counters, writeOpts));
    out.push(...await writeRelationChunk(context, user, bundle.relations, counters, writeOpts));
  }
  return out;
}, (bundle) => bundle.entities.length + bundle.relations.length);

const ownerOfDoc = (doc: any) => ({ owner_id: doc.internal_id, owner_index: doc._index, owner_type: doc.entity_type, owner_standard_id: doc.standard_id });
const keysOfStored = (doc: any) => [...identityKeys(doc.entity_type, { ...doc, stix_id: doc.standard_id }), doc.internal_id];

// Delete: tombstones first (new references are refused from now on), then a refresh so the platform's delete finds
// relationships written without refresh, then the platform delete. Relationships that still slip in between are
// removed by the settler when it finds the tombstone.
export const deleteEntity = async (entity: { internal_id: string; _index: string }) => {
  const raw = (await mgetRaw([{ id: entity.internal_id, index: entity._index }])).get(entity.internal_id);
  if (!raw) return;
  const [doc] = await toElements([raw]);
  await setKeys(keysOfStored(doc).map((key) => ({ key, owner: ownerOfDoc(doc), state: 'deleted' as const })));
  await elRefreshIndices([...READ_DATA_INDICES, ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED]);
  await deleteElementById(testContext, ADMIN_USER, entity.internal_id, doc.entity_type);
};

// Rename through the platform's update path (user edits stay on it), then the new keys point to the same object.
// The old keys keep pointing to it: a feed still sending the old name lands on the same object, as today.
export const renameEntity = async (entity: { internal_id: string; _index: string; entity_type: string }, name: string) => {
  await updateAttribute(testContext, ADMIN_USER, entity.internal_id, entity.entity_type, [{ key: 'name', value: [name] }]);
  const raw = (await mgetRaw([{ id: entity.internal_id, index: entity._index }])).get(entity.internal_id);
  const [doc] = await toElements([raw as any]);
  await setKeys(keysOfStored(doc).map((key) => ({ key, owner: ownerOfDoc(doc) })));
  return doc;
};

// Drop the lock-free state of this platform (identity index, pending relationships, settler queue, applied sets),
// for a platform whose data was wiped: kept, it would point to objects that no longer exist
export const resetLockFreeState = async () => {
  await elDeleteIndices([IDENTITY_INDEX, PENDING_INDEX]);
  await clearQueue();
  const client = getClientBase() as any;
  await client.del(`${REDIS_PREFIX}lockfree:backfill:done`);
  let cursor = '0';
  do {
    const [next, keys] = await client.scan(cursor, 'MATCH', `${REDIS_PREFIX}lockfree:applied:*`, 'COUNT', 1000);
    if (keys.length > 0) await client.del(...keys);
    cursor = next;
  } while (cursor !== '0');
};

export const countersSum = (list: Counters[]) => {
  const out: Counters = {};
  list.forEach((c) => Object.entries(c).forEach(([k, v]) => add(out, k, v)));
  return out;
};
