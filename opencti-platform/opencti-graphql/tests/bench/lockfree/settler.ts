// Settler: applies the work the write path leaves for later, read from the durable queue (queue.ts).
//  - endpoint tasks: add or remove ids in the rel_* lists of an entity, all tasks of one entity in one update;
//    a task whose entity was deleted removes the relationship it came from;
//  - reconcile tasks: two entities found to be one after both were created are merged with today's mergeEntities;
//  - relation-reconcile tasks: two relationships of the same pair found to duplicate each other after both were
//    created: the newer is merged into the older and deleted;
//  - pending relationships (pending.ts) whose ends now exist are written through the normal path.
// Tasks are acknowledged once applied; a settler that stops leaves its tasks to the next one.
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { testContext } from '../../utils/testQuery';
import { EL_DENORMALIZED_REFS_SCRIPT_SOURCE, buildDenormalizedRefsScriptParams, elRawBulk } from '../../../src/database/engine';
import { storeDeleteEvent } from '../../../src/database/stream/stream-handler';
import { inferIndexFromConceptType } from '../../../src/database/utils';
import { SYSTEM_USER } from '../../../src/utils/access';
import { buildRefRelationKey, ID_INTERNAL } from '../../../src/schema/general';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { now } from '../../../src/utils/format';
import { benchTimer } from '../../../src/utils/bench-timing';
import { pool } from '../bench-utils';
import { getClientBase } from '../../../src/database/redis';
import { REDIS_PREFIX } from '../../../src/config/conf';
import { lookupKeys } from './identity';
import { loadWithRefs, mgetRaw, toElements } from './load';
import { processPending } from './pending';
import { reconcileEntities } from './reconcile';
import { pairKey, removeFromPair } from './pairs';
import { ackTasks, type EndpointTask, PARTITIONS, type QueuedTask, readTasks, type ReconcileTask, type RelationReconcileTask } from './queue';
import { add, type Counters, newCounters } from './store';
import { deleteMetaRelations, upsertLockFree } from './upsert';

const appliedKey = (t: EndpointTask) => `${t.op}|${t.endpoint}|${t.relation_type}|${t.relation ?? t.other}`;
const APPLIED_TTL_SECONDS = 7 * 24 * 3600;
// A task delivered again after it was applied (the settler stopped before acknowledging) is skipped.
// Checked before applying, recorded after: a stop between the two can apply a task twice, never lose one.
const appliedSetKey = (t: EndpointTask) => `${REDIS_PREFIX}lockfree:applied:${t.endpoint}`;
const findApplied = async (tasks: EndpointTask[]) => {
  const already = new Set<string>();
  if (tasks.length === 0) return already;
  const pipeline = getClientBase().pipeline();
  tasks.forEach((t) => pipeline.call('SISMEMBER', appliedSetKey(t), appliedKey(t)));
  const results = await pipeline.exec();
  tasks.forEach((t, i) => {
    if (Number(results?.[i]?.[1]) === 1) already.add(appliedKey(t));
  });
  return already;
};
const recordApplied = async (tasks: EndpointTask[]) => {
  if (tasks.length === 0) return;
  const pipeline = getClientBase().pipeline();
  tasks.forEach((t) => {
    pipeline.call('SADD', appliedSetKey(t), appliedKey(t));
    pipeline.call('EXPIRE', appliedSetKey(t), APPLIED_TTL_SECONDS);
  });
  await pipeline.exec();
};
const REMOVE_SCRIPT = 'for (r in params.remove) { if (ctx._source[r.field] != null) { ctx._source[r.field].removeIf(x -> r.ids.contains(x)); } }';

export interface SettlerOptions {
  partitions?: number[]; // queue partitions this settler owns (default: all)
  consumer?: string; // consumer name in the group (a restarted settler can reuse its name or take a new one)
  parallelBulks?: number; // update bulks sent at the same time
  claimIdleMs?: number; // take over tasks another settler left pending for this long
  pendingTtlMs?: number; // drop pending relationships waiting longer than this
  resolveUser?: (userId: string) => Promise<AuthUser>; // to write pending relationships as the user who sent them
  writePending?: (context: AuthContext, user: AuthUser, inputs: Record<string, any>[], counters: Counters) => Promise<void>;
}

// A relationship with its ends, for its stream event: the ends as stored, or rebuilt from their tombstone
const withEnds = async (relation: any) => {
  const full = await loadWithRefs(testContext, SYSTEM_USER, relation);
  const owners = await lookupKeys([relation.fromId, relation.toId].filter(Boolean));
  const stub = (id: string, role: string) => {
    const connection = (relation.connections ?? []).find((c: any) => c.role.endsWith(role));
    const owner = owners.get(id);
    return { internal_id: id, id, entity_type: owner?.owner_type ?? connection?.types?.[0], standard_id: owner?.owner_standard_id, name: connection?.name };
  };
  return {
    ...full,
    from: full.from ?? stub(relation.fromId, '_from'),
    to: full.to ?? stub(relation.toId, '_to'),
    fromType: (full.from ?? stub(relation.fromId, '_from')).entity_type,
    toType: (full.to ?? stub(relation.toId, '_to')).entity_type,
  };
};

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
    const reconcile = tasks.filter((t) => t.task.kind === 'reconcile');
    const relationReconcile = tasks.filter((t) => t.task.kind === 'relation-reconcile');
    const endpoint = tasks.filter((t) => t.task.kind === 'endpoint');
    const done: QueuedTask[] = [];
    for (const t of reconcile) {
      await this.reconcileEntities(t.task as ReconcileTask);
      done.push(t);
    }
    for (const t of relationReconcile) {
      await this.reconcileRelations(t.task as RelationReconcileTask);
      done.push(t);
    }
    bench.step('reconcile');
    done.push(...await this.applyEndpointTasks(endpoint));
    bench.step('endpoints');
    await ackTasks(done);
    if (this.partitions.includes(0) && this.opts.writePending && this.opts.resolveUser) {
      const outcome = await processPending(async (userId, inputs) => {
        const user = await (this.opts.resolveUser as any)(userId);
        await (this.opts.writePending as any)(testContext, user, inputs, this.counters);
      }, { ttlMs: this.opts.pendingTtlMs ?? 24 * 3600 * 1000 });
      add(this.counters, 'pending_resolved', outcome.resolved);
      add(this.counters, 'pending_refused_deleted', outcome.refused_deleted);
      add(this.counters, 'pending_expired', outcome.expired);
    }
    bench.step('pending');
    bench.total();
    return done.length;
  }

  // All the tasks of one entity in one update; tasks of a deleted entity remove their relationship
  private async applyEndpointTasks(queued: QueuedTask[]): Promise<QueuedTask[]> {
    if (queued.length === 0) return [];
    const byEndpoint = R.groupBy((t: QueuedTask) => (t.task as EndpointTask).endpoint, queued);
    const refs = Object.values(byEndpoint).map((group) => ({ id: (group![0].task as EndpointTask).endpoint, index: (group![0].task as EndpointTask).index }));
    const found = await mgetRaw(refs, { light: true });
    // Exactly once: each (entity, relationship) pair is applied once, even when a task is delivered again
    const alreadyApplied = await findApplied(queued.map((t) => t.task as EndpointTask).filter((t) => found.has(t.endpoint)));
    const body: any[] = [];
    const applied: QueuedTask[] = [];
    const updatedAt = now();
    const missing: QueuedTask[][] = [];
    Object.entries(byEndpoint).forEach(([endpointId, group]) => {
      const raw = found.get(endpointId);
      if (!raw) {
        missing.push(group ?? []);
        return;
      }
      const tasks = (group ?? []).map((t) => t.task as EndpointTask).filter((t) => !alreadyApplied.has(appliedKey(t)));
      const adds = tasks.filter((t) => t.op === 'add');
      const removes = tasks.filter((t) => t.op === 'remove');
      if (adds.length > 0) {
        const byRelation = R.groupBy((t: EndpointTask) => t.relation_type, adds);
        const targets = Object.entries(byRelation).map(([relation, list]) => ({
          relation,
          field: ID_INTERNAL,
          elements: (list ?? []).map((t) => ({ id: t.other, side: t.side, type: t.type })),
        }));
        // As today: one entry per relationship (distinct only for unidirectional refs)
        const params = buildDenormalizedRefsScriptParams(targets, updatedAt);
        body.push({ update: { _index: raw._index, _id: endpointId, retry_on_conflict: 20 } }, { script: { source: EL_DENORMALIZED_REFS_SCRIPT_SOURCE, params } });
      }
      if (removes.length > 0) {
        const remove = Object.entries(R.groupBy((t: EndpointTask) => t.relation_type, removes))
          .map(([relation, list]) => ({ field: buildRefRelationKey(relation), ids: R.uniq((list ?? []).map((t) => t.other)) }));
        body.push({ update: { _index: raw._index, _id: endpointId, retry_on_conflict: 20 } }, { script: { source: REMOVE_SCRIPT, params: { remove } } });
      }
      applied.push(...(group ?? []));
      add(this.counters, 'endpoint_updates');
    });
    await pool(R.splitEvery(2000, body), this.opts.parallelBulks ?? 4, async (chunk) => {
      const response: any = await elRawBulk(testContext, { refresh: false, body: chunk });
      const failed = response.items.find((i: any) => (Object.values(i)[0] as any).status >= 300 && (Object.values(i)[0] as any).status !== 404);
      if (failed) throw new Error(`Settle failed: ${JSON.stringify(failed)}`);
    });
    await recordApplied(applied.map((t) => t.task as EndpointTask));
    // Entities that do not exist: deleted (their keys are tombstones) -> remove the relationships that point to them
    if (missing.length > 0) {
      const owners = await lookupKeys(missing.map((group) => (group[0].task as EndpointTask).endpoint));
      for (const group of missing) {
        const task = group[0].task as EndpointTask;
        if (owners.get(task.endpoint)?.state === 'deleted') {
          for (const t of group) {
            const relation = (t.task as EndpointTask).relation;
            if (relation) await this.deleteRelation(relation, (t.task as EndpointTask).relation_index ?? inferIndexFromConceptType(task.relation_type));
          }
          applied.push(...group);
        } else {
          add(this.counters, 'endpoint_waiting');
        }
      }
    }
    return applied;
  }

  private async deleteRelation(id: string, index: string) {
    const raw = (await mgetRaw([{ id, index }])).get(id);
    if (!raw) return;
    const [relation] = await toElements([raw]);
    for (const ref of schemaRelationsRefDefinition.getRelationsRef(relation.entity_type)) {
      const targets = [].concat(relation[ref.databaseName] ?? []);
      await deleteMetaRelations(relation.internal_id, ref.databaseName, targets);
    }
    await elRawBulk(testContext, { refresh: false, body: [{ delete: { _index: raw._index, _id: raw._id } }] });
    const fromId = relation.fromId;
    const toId = relation.toId;
    await removeFromPair(pairKey(relation.entity_type, fromId, toId), relation.internal_id);
    // The other end may list this end: remove it there
    const ends = (relation.connections ?? []).map((c: any) => ({ id: c.internal_id, index: inferIndexFromConceptType(c.types[0]) }));
    const body = ends.flatMap((end: any) => {
      const other = ends.find((e: any) => e.id !== end.id);
      if (!other) return [];
      const remove = [{ field: buildRefRelationKey(relation.entity_type), ids: [other.id] }];
      return [{ update: { _index: end.index, _id: end.id, retry_on_conflict: 20 } }, { script: { source: REMOVE_SCRIPT, params: { remove } } }];
    });
    if (body.length > 0) await elRawBulk(testContext, { refresh: false, body });
    await storeDeleteEvent(testContext, SYSTEM_USER, await withEnds(relation));
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
    const drop = await loadWithRefs(testContext, SYSTEM_USER, dropElement);
    const patch: Record<string, any> = R.omit(['_index', '_id', 'id', 'internal_id', 'standard_id', 'i_raw', 'connections', 'from', 'to', 'fromId', 'toId'], drop);
    await upsertLockFree(testContext, SYSTEM_USER, task.keep, drop.entity_type, patch, this.counters);
    await this.deleteRelationKeepingEnds(drop, dropRaw._index);
    await removeFromPair(task.pair, task.drop.id);
    add(this.counters, 'relations_reconciled');
  }

  private async deleteRelationKeepingEnds(relation: any, index: string) {
    for (const ref of schemaRelationsRefDefinition.getRelationsRef(relation.entity_type)) {
      await deleteMetaRelations(relation.internal_id, ref.databaseName, [].concat(relation[ref.databaseName] ?? []).map((r: any) => r.internal_id ?? r));
    }
    await elRawBulk(testContext, { refresh: false, body: [{ delete: { _index: index, _id: relation.internal_id } }] });
    await storeDeleteEvent(testContext, SYSTEM_USER, await withEnds(relation));
  }
}

export const settlerCounters = (settlers: Settler[]) => {
  const out: Counters = {};
  settlers.forEach((s) => Object.entries(s.counters).forEach(([k, v]) => add(out, k, v)));
  return out;
};
