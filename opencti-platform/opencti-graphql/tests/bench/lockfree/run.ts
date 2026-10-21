// Entry points of the lock-free prototype for the scenarios: write inputs with a background settler, and the
// slow paths the prototype keeps on the platform (delete, rename) wrapped with their identity index updates.
import * as R from 'ramda';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { deleteElementById, updateAttribute } from '../../../src/database/middleware';
import { elRefreshIndices } from '../../../src/database/engine';
import { READ_DATA_INDICES, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../../src/database/utils';
import { now as nowMs, phaseSummary, pool, resetPhases, round } from '../bench-utils';
import { identityKeys, setKeys } from './identity';
import { add, type Counters, fetchDocs, newCounters } from './store';
import { Settler } from './settler';
import { type EntityInput, type RelationInput, writeEntityChunk, writeRelationChunk } from './writer';

export interface RunOptions {
  chunkSize: number; // objects per write call; 1 = one call per object, like one worker message
  concurrency: number; // calls in flight
  settleEveryMs: number; // settler period while writing
  settler?: Settler; // reuse one settler across runs (out-of-order arrival)
  settlers?: number; // independent settlers, one per writer share (as several platform nodes)
  noSettle?: boolean; // leave the settler work pending (to write more before it runs)
}

// A reconciliation or a re-point queues endpoint work for the next pass
export const settleAll = async (settlers: Settler[]) => {
  for (let pass = 0; pass < 3; pass += 1) {
    await Promise.all(settlers.map((s) => s.flush()));
  }
  await elRefreshIndices([...READ_DATA_INDICES, ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED]);
};

const writeAll = async <T>(inputs: T[], opts: RunOptions, write: (chunk: T[], settler: Settler, counters: Counters) => Promise<void>, sizeOf: (item: T) => number = () => 1) => {
  const objects = inputs.reduce((n, item) => n + sizeOf(item), 0);
  const counters = newCounters();
  const settlers = opts.settler ? [opts.settler] : [...Array(opts.settlers ?? 1)].map(() => new Settler());
  const chunks = R.splitEvery(opts.chunkSize, inputs);
  resetPhases();
  const startedAt = Date.now();
  const start = nowMs();
  let writing = !opts.noSettle;
  // The period sleep ends early when the writes are done, so the final settle does not wait for it
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
  await pool(chunks, opts.concurrency, async (chunk, i) => write(chunk, settlers[i % settlers.length], counters));
  const written = nowMs();
  writing = false;
  stopWaiting();
  await Promise.all(loops);
  if (!opts.noSettle) await settleAll(settlers);
  const settled = nowMs();
  const settlerCounters: Counters = {};
  settlers.forEach((s) => Object.entries(s.counters).forEach(([k, v]) => add(settlerCounters, k, v)));
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
    created: (counters.entities_created ?? 0) + (counters.relations_created ?? 0),
    merged: (counters.entities_merged ?? 0) + (counters.relations_merged ?? 0),
    writer: counters,
    settler: { ...settlerCounters, still_pending: settlers.reduce((n, s) => n + s.pending, 0) },
    phases_ms: phaseSummary(),
    started_at: startedAt,
    ended_at: Date.now(),
  };
};

export const writeEntities = (inputs: EntityInput[], opts: RunOptions) => writeAll(inputs, opts, writeEntityChunk);
export const writeRelations = (inputs: RelationInput[], opts: RunOptions) => writeAll(inputs, opts, writeRelationChunk);

// A bundle as a connector sends it: its entities, then the relationships between them, in one chunk.
// chunkSize counts bundles; throughput counts objects.
export interface Bundle { entities: EntityInput[]; relations: RelationInput[] }
export const writeBundles = (bundles: Bundle[], opts: RunOptions) => writeAll(bundles, opts, async (chunk, settler, counters) => {
  for (const bundle of chunk) {
    await writeEntityChunk(bundle.entities, settler, counters);
    await writeRelationChunk(bundle.relations, settler, counters);
  }
}, (bundle) => bundle.entities.length + bundle.relations.length);

const keysOfStored = (doc: any) => [...identityKeys(doc.entity_type, { ...doc, stix_id: doc.standard_id }), doc.internal_id];
const ownerOf = (doc: any) => ({ owner_id: doc.internal_id, owner_index: doc._index, owner_type: doc.entity_type, owner_standard_id: doc.standard_id });

// Delete: tombstones first (new writes referencing it are refused from now on), then a refresh so the
// platform's delete finds the relationships written without refresh, then the platform delete.
// Relationships that still slip in between are removed by the settler when it finds the tombstone.
export const deleteEntity = async (entity: { internal_id: string; _index: string }) => {
  const doc = (await fetchDocs([{ index: entity._index, id: entity.internal_id }])).get(entity.internal_id);
  await setKeys(keysOfStored(doc).map((key) => ({ key, owner: ownerOf(doc), state: 'deleted' as const })));
  await elRefreshIndices([...READ_DATA_INDICES, ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED]);
  await deleteElementById(testContext, ADMIN_USER, entity.internal_id, doc.entity_type);
};

// Rename through the platform's update path (user edits stay on it), then claim the new keys for the same owner.
// The old keys keep pointing to it: a feed still sending the old name or STIX id lands on the same object.
export const renameEntity = async (entity: { internal_id: string; _index: string; entity_type: string }, name: string) => {
  await updateAttribute(testContext, ADMIN_USER, entity.internal_id, entity.entity_type, [{ key: 'name', value: [name] }]);
  const doc = (await fetchDocs([{ index: entity._index, id: entity.internal_id }])).get(entity.internal_id);
  await setKeys(keysOfStored(doc).map((key) => ({ key, owner: ownerOf(doc) })));
  return doc;
};
