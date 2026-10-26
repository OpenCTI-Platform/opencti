// Settler: applies the work the write path leaves for later, read from the durable queue (queue.ts).
//  - endpoint tasks: add or remove ids in the rel_* lists of an entity, all tasks of one entity in one update;
//    a task whose entity was deleted removes the relationship it came from;
//  - reconcile tasks: two entities found to be one after both were created are merged with today's mergeEntities;
//  - relation-reconcile tasks: two relationships of the same pair found to duplicate each other after both were
//    created: the newer is merged into the older and deleted;
//  - pending relationships (pending.ts) whose ends now exist are written through the normal path.
// Tasks are acknowledged once applied; a settler that stops leaves its tasks to the next one.
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { lockfreeContext, pool } from './context';
import { EL_DENORMALIZED_REFS_SCRIPT_SOURCE, buildDenormalizedRefsScriptParams, elRawBulk } from '../engine';
import { storeDeleteEvent } from '../stream/stream-handler';
import { inferIndexFromConceptType } from '../utils';
import { SYSTEM_USER } from '../../utils/access';
import { buildRefRelationKey, ID_INTERNAL } from '../../schema/general';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { now } from '../../utils/format';
import { benchTimer } from '../../utils/bench-timing';
import { getClientBase } from '../redis';
import { lookupKeys } from './identity';
import { loadWithRefs, mgetRaw, toElements } from './load';
import { processPending } from './pending';
import { reconcileEntities } from './reconcile';
import { pairKey, removeFromPair } from './pairs';
import { ackTasks, type EndpointTask, PARTITIONS, type QueuedTask, readTasks, type ReconcileTask, type RelationReconcileTask } from './queue';
import { add, type Counters, newCounters } from './store';
import { deleteMetaRelations, upsertLockFree } from './upsert';

const BULK_LINES = 2000; // lines per update bulk (two per updated document)
const RETRY_ON_CONFLICT = 20;
const APPLIED_TTL_SECONDS = 7 * 24 * 3600;

const endpointTaskOf = (queued: QueuedTask) => queued.task as EndpointTask;

// A task delivered again after it was applied (the settler stopped before acknowledging) is skipped.
// Checked before applying, recorded after: a stop between the two can apply a task twice, never lose one.
const appliedMember = (task: EndpointTask) => `${task.op}|${task.endpoint}|${task.relation_type}|${task.relation ?? task.other}`;
const appliedSetKey = (task: EndpointTask) => `lockfree:applied:${task.endpoint}`; // prefixed by the client
const findApplied = async (tasks: EndpointTask[]) => {
  const alreadyApplied = new Set<string>();
  if (tasks.length === 0) return alreadyApplied;
  const pipeline = getClientBase().pipeline();
  tasks.forEach((task) => pipeline.call('SISMEMBER', appliedSetKey(task), appliedMember(task)));
  const results = await pipeline.exec();
  tasks.forEach((task, i) => {
    if (Number(results?.[i]?.[1]) === 1) alreadyApplied.add(appliedMember(task));
  });
  return alreadyApplied;
};
const recordApplied = async (tasks: EndpointTask[]) => {
  if (tasks.length === 0) return;
  const pipeline = getClientBase().pipeline();
  tasks.forEach((task) => {
    pipeline.call('SADD', appliedSetKey(task), appliedMember(task));
    pipeline.call('EXPIRE', appliedSetKey(task), APPLIED_TTL_SECONDS);
  });
  await pipeline.exec();
};

const REMOVE_SCRIPT = 'for (r in params.remove) { if (ctx._source[r.field] != null) { ctx._source[r.field].removeIf(x -> r.ids.contains(x)); } }';
const removeIdsLines = (index: string, id: string, remove: { field: string; ids: string[] }[]) => [
  { update: { _index: index, _id: id, retry_on_conflict: RETRY_ON_CONFLICT } },
  { script: { source: REMOVE_SCRIPT, params: { remove } } },
];

// Bulk lines applying the tasks of one entity: one update appending the ids of its add tasks, one removing the ids
// of its remove tasks
const endpointUpdateLines = (index: string, endpointId: string, tasks: EndpointTask[], updatedAt: string) => {
  const lines: any[] = [];
  const adds = tasks.filter((task) => task.op === 'add');
  const removes = tasks.filter((task) => task.op === 'remove');
  if (adds.length > 0) {
    const targets = Object.entries(R.groupBy((task: EndpointTask) => task.relation_type, adds)).map(([relation, relationTasks]) => ({
      relation,
      field: ID_INTERNAL,
      elements: (relationTasks ?? []).map((task) => ({ id: task.other, side: task.side, type: task.type })),
    }));
    // As today: one entry per relationship (distinct only for unidirectional refs)
    const params = buildDenormalizedRefsScriptParams(targets, updatedAt);
    lines.push({ update: { _index: index, _id: endpointId, retry_on_conflict: RETRY_ON_CONFLICT } }, { script: { source: EL_DENORMALIZED_REFS_SCRIPT_SOURCE, params } });
  }
  if (removes.length > 0) {
    const remove = Object.entries(R.groupBy((task: EndpointTask) => task.relation_type, removes))
      .map(([relation, relationTasks]) => ({ field: buildRefRelationKey(relation), ids: R.uniq((relationTasks ?? []).map((task) => task.other)) }));
    lines.push(...removeIdsLines(index, endpointId, remove));
  }
  return lines;
};

// A relationship with its ends, for its stream event: the ends as stored, or rebuilt from their tombstone
const withEnds = async (relation: any) => {
  const full = await loadWithRefs(lockfreeContext, SYSTEM_USER, relation);
  const owners = await lookupKeys([relation.fromId, relation.toId].filter(Boolean));
  const stub = (id: string, role: string) => {
    const connection = (relation.connections ?? []).find((c: any) => c.role.endsWith(role));
    const owner = owners.get(id);
    return { internal_id: id, id, entity_type: owner?.owner_type ?? connection?.types?.[0], standard_id: owner?.owner_standard_id, name: connection?.name };
  };
  const from = full.from ?? stub(relation.fromId, '_from');
  const to = full.to ?? stub(relation.toId, '_to');
  return { ...full, from, to, fromType: from.entity_type, toType: to.entity_type };
};

interface SettlerOptions {
  partitions?: number[]; // queue partitions this settler owns (default: all)
  consumer?: string; // consumer name in the group (a restarted settler can reuse its name or take a new one)
  parallelBulks?: number; // update bulks sent at the same time
  claimIdleMs?: number; // take over tasks another settler left pending for this long
  pendingTtlMs?: number; // drop pending relationships waiting longer than this
  resolveUser?: (userId: string) => Promise<AuthUser>; // to write pending relationships as the user who sent them
  writePending?: (context: AuthContext, user: AuthUser, inputs: Record<string, any>[], counters: Counters) => Promise<void>;
}

export class Settler {
  counters: Counters = newCounters();

  private partitions: number[];

  private consumer: string;

  constructor(private opts: SettlerOptions = {}) {
    this.partitions = opts.partitions ?? [...Array(PARTITIONS).keys()];
    this.consumer = opts.consumer ?? `settler-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
  }

  // One round; returns how many tasks were applied
  async flush(): Promise<number> {
    const bench = benchTimer('lf_settle');
    add(this.counters, 'flushes');
    const tasks = await readTasks(this.partitions, this.consumer, 20000, this.opts.claimIdleMs ?? 30000);
    bench.step('read');
    const done = await this.applyReconcileTasks(tasks);
    bench.step('reconcile');
    done.push(...await this.applyEndpointTasks(tasks.filter((queued) => queued.task.kind === 'endpoint')));
    bench.step('endpoints');
    await ackTasks(done);
    await this.writeResolvedPending();
    bench.step('pending');
    bench.total();
    return done.length;
  }

  // Merges, one at a time: entities first, then relationships
  private async applyReconcileTasks(tasks: QueuedTask[]): Promise<QueuedTask[]> {
    const done: QueuedTask[] = [];
    for (const queued of tasks.filter((t) => t.task.kind === 'reconcile')) {
      await this.reconcileEntities(queued.task as ReconcileTask);
      done.push(queued);
    }
    for (const queued of tasks.filter((t) => t.task.kind === 'relation-reconcile')) {
      await this.reconcileRelations(queued.task as RelationReconcileTask);
      done.push(queued);
    }
    return done;
  }

  // Pending relationships whose ends now exist, written by the settler owning partition 0
  private async writeResolvedPending() {
    const { resolveUser, writePending } = this.opts;
    if (!this.partitions.includes(0) || !writePending || !resolveUser) return;
    const outcome = await processPending(async (userId, inputs) => {
      const user = await resolveUser(userId);
      await writePending(lockfreeContext, user, inputs, this.counters);
    }, { ttlMs: this.opts.pendingTtlMs ?? 24 * 3600 * 1000 });
    add(this.counters, 'pending_resolved', outcome.resolved);
    add(this.counters, 'pending_refused_deleted', outcome.refused_deleted);
    add(this.counters, 'pending_expired', outcome.expired);
  }

  // All the tasks of one entity in one update; tasks of a deleted entity remove their relationship
  private async applyEndpointTasks(queued: QueuedTask[]): Promise<QueuedTask[]> {
    if (queued.length === 0) return [];
    const groups = Object.entries(R.groupBy((t: QueuedTask) => endpointTaskOf(t).endpoint, queued))
      .map(([endpointId, group]) => ({ endpointId, group: group ?? [] }));
    const endpointRefs = groups.map(({ group }) => ({ id: endpointTaskOf(group[0]).endpoint, index: endpointTaskOf(group[0]).index }));
    const found = await mgetRaw(endpointRefs, { light: true });
    // Exactly once: each (entity, relationship) pair is applied once, even when a task is delivered again
    const alreadyApplied = await findApplied(queued.map(endpointTaskOf).filter((task) => found.has(task.endpoint)));
    const updatedAt = now();
    const body: any[] = [];
    const applied: QueuedTask[] = [];
    const missing: QueuedTask[][] = [];
    groups.forEach(({ endpointId, group }) => {
      const raw = found.get(endpointId);
      if (!raw) {
        missing.push(group);
        return;
      }
      const tasks = group.map(endpointTaskOf).filter((task) => !alreadyApplied.has(appliedMember(task)));
      body.push(...endpointUpdateLines(raw._index, endpointId, tasks, updatedAt));
      applied.push(...group);
      add(this.counters, 'endpoint_updates');
    });
    await pool(R.splitEvery(BULK_LINES, body), this.opts.parallelBulks ?? 4, async (chunk) => {
      const response: any = await elRawBulk(lockfreeContext, { refresh: false, body: chunk });
      const failed = response.items.find((item: any) => {
        const { status } = Object.values(item)[0] as any;
        return status >= 300 && status !== 404; // 404: the document no longer exists
      });
      if (failed) throw new Error(`Settle failed: ${JSON.stringify(failed)}`);
    });
    await recordApplied(applied.map(endpointTaskOf));
    applied.push(...await this.settleMissingEndpoints(missing));
    return applied;
  }

  // Entities that do not exist: deleted (their keys are tombstones) -> remove the relationships that point to them;
  // otherwise their tasks stay unacknowledged, for a later round
  private async settleMissingEndpoints(missing: QueuedTask[][]): Promise<QueuedTask[]> {
    if (missing.length === 0) return [];
    const owners = await lookupKeys(missing.map((group) => endpointTaskOf(group[0]).endpoint));
    const settled: QueuedTask[] = [];
    for (const group of missing) {
      const first = endpointTaskOf(group[0]);
      if (owners.get(first.endpoint)?.state === 'deleted') {
        for (const queued of group) {
          const task = endpointTaskOf(queued);
          if (task.relation) await this.deleteRelation(task.relation, task.relation_index ?? inferIndexFromConceptType(first.relation_type));
        }
        settled.push(...group);
      } else {
        add(this.counters, 'endpoint_waiting');
      }
    }
    return settled;
  }

  // A relationship whose end was deleted
  private async deleteRelation(id: string, index: string) {
    const raw = (await mgetRaw([{ id, index }])).get(id);
    if (!raw) return;
    const [relation] = await toElements([raw]);
    for (const ref of schemaRelationsRefDefinition.getRelationsRef(relation.entity_type)) {
      const targets = [].concat(relation[ref.databaseName] ?? []);
      await deleteMetaRelations(relation.internal_id, ref.databaseName, targets);
    }
    await elRawBulk(lockfreeContext, { refresh: false, body: [{ delete: { _index: raw._index, _id: raw._id } }] });
    await removeFromPair(pairKey(relation.entity_type, relation.fromId, relation.toId), relation.internal_id);
    // The other end may list this end: remove it there
    const ends: { id: string; index: string }[] = (relation.connections ?? [])
      .map((connection: any) => ({ id: connection.internal_id, index: inferIndexFromConceptType(connection.types[0]) }));
    const body = ends.flatMap((end) => {
      const other = ends.find((candidate) => candidate.id !== end.id);
      if (!other) return [];
      return removeIdsLines(end.index, end.id, [{ field: buildRefRelationKey(relation.entity_type), ids: [other.id] }]);
    });
    if (body.length > 0) await elRawBulk(lockfreeContext, { refresh: false, body });
    await storeDeleteEvent(lockfreeContext, SYSTEM_USER, await withEnds(relation));
    add(this.counters, 'relations_deleted_dangling');
  }

  // Two entities found to be one after both were created: today's merge
  private async reconcileEntities(task: ReconcileTask) {
    add(this.counters, 'entities_reconciled', await reconcileEntities([task.loser], task.winner));
  }

  // Two relationships of a pair found to duplicate each other: merge the newer into the older, delete the newer
  private async reconcileRelations(task: RelationReconcileTask) {
    const raws = await mgetRaw([task.keep, task.drop]);
    const dropRaw = raws.get(task.drop.id);
    if (!dropRaw || !raws.get(task.keep.id)) return;
    const [dropElement] = await toElements([dropRaw]);
    const drop = await loadWithRefs(lockfreeContext, SYSTEM_USER, dropElement);
    // Not merged: the duplicate's identity, ends and raw document
    const patch: Record<string, any> = R.omit(['_index', '_id', 'id', 'internal_id', 'standard_id', 'i_raw', 'connections', 'from', 'to', 'fromId', 'toId'], drop);
    await upsertLockFree(lockfreeContext, SYSTEM_USER, task.keep, drop.entity_type, patch, this.counters);
    await this.deleteRelationKeepingEnds(drop, dropRaw._index);
    await removeFromPair(task.pair, task.drop.id);
    add(this.counters, 'relations_reconciled');
  }

  // A duplicate relationship: its ends keep listing the pair, which the kept relationship still links
  private async deleteRelationKeepingEnds(relation: any, index: string) {
    for (const ref of schemaRelationsRefDefinition.getRelationsRef(relation.entity_type)) {
      await deleteMetaRelations(relation.internal_id, ref.databaseName, [].concat(relation[ref.databaseName] ?? []).map((target: any) => target.internal_id ?? target));
    }
    await elRawBulk(lockfreeContext, { refresh: false, body: [{ delete: { _index: index, _id: relation.internal_id } }] });
    await storeDeleteEvent(lockfreeContext, SYSTEM_USER, await withEnds(relation));
  }
}

export const settlerCounters = (settlers: Settler[]) => {
  const total: Counters = {};
  settlers.forEach((settler) => Object.entries(settler.counters).forEach(([key, value]) => add(total, key, value)));
  return total;
};
