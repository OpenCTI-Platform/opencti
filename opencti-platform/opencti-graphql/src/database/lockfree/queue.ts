// Durable work queue of the settler: Redis streams, one per partition, split by entity id so that one entity's
// work always lands in the same partition. Settlers read through a consumer group: an item is acknowledged only
// once applied, items a settler read but never acknowledged stay pending for it, and items left pending by a
// settler that stopped are claimed by another one after `claimIdleMs`.
import { getClientBase } from '../../database/redis';
import { REDIS_PREFIX } from '../../config/conf';
import type { Owner } from './identity';

export const PARTITIONS = 4;
const GROUP = 'settlers';
// The stream field holding the serialized task
const TASK_FIELD = 't';
// The client adds the platform's key prefix (ioredis keyPrefix)
export const streamName = (partition: number) => `lockfree:settle:${partition}`;

// Add or remove `other` in the rel_<relation_type> list of `endpoint`; `relation` is the relationship it comes from
export interface EndpointTask { kind: 'endpoint'; op: 'add' | 'remove'; endpoint: string; index: string; type: string; relation_type: string; other: string; side: string; relation?: string; relation_index?: string }
// Two objects found to be one after both were created: merge loser into winner with the platform's merge
export interface ReconcileTask { kind: 'reconcile'; loser: Owner; winner: Owner }
// Two relationships found to duplicate each other after both were created (same pair, inside the window)
export interface RelationReconcileTask { kind: 'relation-reconcile'; keep: { id: string; index: string }; drop: { id: string; index: string }; pair: string }
export type Task = EndpointTask | ReconcileTask | RelationReconcileTask;
export interface QueuedTask { partition: number; id: string; task: Task }

// A stream entry as Redis returns it: [entry id, [field, value, field, value...]]
type StreamEntry = [string, string[]];

const partitionOf = (id: string) => parseInt(id.replace(/-/g, '').slice(0, 8), 16) % PARTITIONS;
const taskPartition = (task: Task) => {
  if (task.kind === 'endpoint') return partitionOf(task.endpoint);
  if (task.kind === 'reconcile') return partitionOf(task.loser.owner_id);
  return partitionOf(task.drop.id);
};

const ensuredGroups = new Set<number>();
const ensureGroup = async (partition: number) => {
  if (ensuredGroups.has(partition)) return;
  try {
    // keyPrefix is not applied to XGROUP: Redis declares its key on the CREATE subcommand, which ioredis does not model
    await getClientBase().call('XGROUP', 'CREATE', `${REDIS_PREFIX}${streamName(partition)}`, GROUP, '0', 'MKSTREAM');
  } catch (e: any) {
    if (!String(e?.message).includes('BUSYGROUP')) throw e;
  }
  ensuredGroups.add(partition);
};

export const enqueue = async (tasks: Task[]) => {
  if (tasks.length === 0) return;
  const pipeline = getClientBase().pipeline();
  tasks.forEach((task) => pipeline.call('XADD', streamName(taskPartition(task)), '*', TASK_FIELD, JSON.stringify(task)));
  const results = await pipeline.exec();
  const failed = (results ?? []).find(([error]) => error);
  if (failed) throw failed[0];
};

const parseEntries = (partition: number, entries: StreamEntry[] | undefined): QueuedTask[] => (entries ?? []).map(([id, fields]) => ({
  partition,
  id,
  task: JSON.parse(fields[fields.indexOf(TASK_FIELD) + 1]) as Task,
}));

// XREADGROUP replies [[stream, entries]] (or nothing), XAUTOCLAIM replies [next cursor, entries, deleted ids]
const readGroupEntries = (reply: any): StreamEntry[] | undefined => reply?.[0]?.[1];
const autoClaimEntries = (reply: any): StreamEntry[] | undefined => reply?.[1];

// This consumer's pending items (retries), items left by stopped consumers, then new items
export const readTasks = async (partitions: number[], consumer: string, count: number, claimIdleMs: number): Promise<QueuedTask[]> => {
  const client = getClientBase();
  const tasks: QueuedTask[] = [];
  for (const partition of partitions) {
    await ensureGroup(partition);
    const key = streamName(partition);
    const ownPending = await client.call('XREADGROUP', 'GROUP', GROUP, consumer, 'COUNT', count, 'STREAMS', key, '0');
    tasks.push(...parseEntries(partition, readGroupEntries(ownPending)));
    const claimed = await client.call('XAUTOCLAIM', key, GROUP, consumer, claimIdleMs, '0-0', 'COUNT', count);
    // An item this consumer already holds can come back from the claim: read once
    const alreadyRead = new Set(tasks.map((task) => task.id));
    tasks.push(...parseEntries(partition, autoClaimEntries(claimed)).filter((task) => !alreadyRead.has(task.id)));
    const fresh = await client.call('XREADGROUP', 'GROUP', GROUP, consumer, 'COUNT', count, 'STREAMS', key, '>');
    tasks.push(...parseEntries(partition, readGroupEntries(fresh)));
  }
  return tasks;
};

// Acknowledge and drop applied items
export const ackTasks = async (tasks: QueuedTask[]) => {
  if (tasks.length === 0) return;
  const pipeline = getClientBase().pipeline();
  const idsByPartition = new Map<number, string[]>();
  tasks.forEach((task) => {
    const ids = idsByPartition.get(task.partition);
    if (ids) ids.push(task.id);
    else idsByPartition.set(task.partition, [task.id]);
  });
  idsByPartition.forEach((ids, partition) => {
    pipeline.call('XACK', streamName(partition), GROUP, ...ids);
    pipeline.call('XDEL', streamName(partition), ...ids);
  });
  await pipeline.exec();
};

// Items not yet acknowledged, in every partition (new and pending)
export const queueDepth = async () => {
  const client = getClientBase();
  let depth = 0;
  for (let partition = 0; partition < PARTITIONS; partition += 1) {
    depth += Number(await client.call('XLEN', streamName(partition)));
  }
  return depth;
};

export const clearQueue = async () => {
  const client = getClientBase();
  for (let partition = 0; partition < PARTITIONS; partition += 1) {
    await client.call('DEL', streamName(partition));
    ensuredGroups.delete(partition);
  }
};
