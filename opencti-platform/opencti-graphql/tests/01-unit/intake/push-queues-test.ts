import { describe, expect, it, vi } from 'vitest';
import {
  consumedPushQueues,
  createOrderedQueuesLeadership,
  createPartitionSlot,
  intakeLockKey,
  parseQueuePartition,
  partitionedPushQueues,
} from '../../../src/intake/workerless/push-queues';

// Several platforms consuming the push queues (multi_writer): each runs its intake under its own
// lock, the ordered queues of the synchronizations go to the platform holding the historical lock.

describe('intake lock key', () => {
  it('should keep the historical key on a single writer and suffix it with the node on a multi writer', () => {
    expect(intakeLockKey('chunk_intake_manager_lock', false, 'node-a')).toEqual('chunk_intake_manager_lock');
    expect(intakeLockKey('chunk_intake_manager_lock', true, 'node-a')).toEqual('chunk_intake_manager_lock_node-a');
    expect(intakeLockKey('chunk_intake_manager_lock', true, 'node-b')).not.toEqual(intakeLockKey('chunk_intake_manager_lock', true, 'node-a'));
  });
});

describe('consumed push queues', () => {
  const queues = ['push_cve', 'push_sync-1', 'push_mitre', 'push_sync'];
  const ordered = new Set(['push_sync-1', 'push_sync']);

  it('should consume every queue with the ordered ones, the others only without', () => {
    expect(consumedPushQueues(queues, ordered, true)).toEqual(queues);
    expect(consumedPushQueues(queues, ordered, false)).toEqual(['push_cve', 'push_mitre']);
  });
});

describe('ordered queues leadership', () => {
  const heldLock = () => {
    const controller = new AbortController();
    return { controller, lock: { signal: controller.signal, unlock: vi.fn().mockResolvedValue(undefined) } };
  };

  it('should lead once the lock is taken and keep it without asking again', async () => {
    const { lock } = heldLock();
    const tryLock = vi.fn().mockResolvedValue(lock);
    const leadership = createOrderedQueuesLeadership(tryLock);
    expect(await leadership.refresh()).toBe(true);
    expect(await leadership.refresh()).toBe(true);
    expect(tryLock).toHaveBeenCalledTimes(1);
    expect(leadership.lost()).toBe(false);
  });

  it('should try again at each refresh while another platform holds the lock', async () => {
    const { lock } = heldLock();
    const tryLock = vi.fn().mockResolvedValueOnce(null).mockResolvedValueOnce(lock);
    const leadership = createOrderedQueuesLeadership(tryLock);
    expect(await leadership.refresh()).toBe(false);
    expect(leadership.lost()).toBe(false);
    expect(await leadership.refresh()).toBe(true);
  });

  it('should be lost for good once the held lock is aborted, and never take it again', async () => {
    const { controller, lock } = heldLock();
    const tryLock = vi.fn().mockResolvedValue(lock);
    const leadership = createOrderedQueuesLeadership(tryLock);
    await leadership.refresh();
    controller.abort();
    expect(await leadership.refresh()).toBe(false);
    expect(leadership.lost()).toBe(true);
    expect(await leadership.refresh()).toBe(false);
    // released by the closing consumer: still lost, the next intake competes again
    await leadership.release();
    expect(await leadership.refresh()).toBe(false);
    expect(tryLock).toHaveBeenCalledTimes(1);
  });

  it('should unlock on release, once', async () => {
    const { lock } = heldLock();
    const leadership = createOrderedQueuesLeadership(vi.fn().mockResolvedValue(lock));
    await leadership.refresh();
    await leadership.release();
    await leadership.release();
    expect(lock.unlock).toHaveBeenCalledTimes(1);
  });
});

describe('queue affinity test: connector groups, one slot per platform', () => {
  const groups = parseQueuePartition(' connector-07, connector-05 | connector-01,connector-02 ||');
  const connectors = [
    { name: 'bench-replay-run-connector-07', queue: 'push_cve' },
    { name: 'bench-replay-run-connector-05', queue: 'push_rw' },
    { name: 'bench-replay-run-connector-01', queue: 'push_mitre' },
    { name: 'bench-replay-run-connector-02', queue: 'push_misp' },
    { name: 'Background task 1 queue', queue: 'push_bg' },
    { name: 'Background task 1 queue', queue: 'push_bg' },
  ];

  it('should parse groups, trimming fragments and dropping empty groups', () => {
    expect(groups).toEqual([['connector-07', 'connector-05'], ['connector-01', 'connector-02']]);
    expect(parseQueuePartition(undefined)).toEqual([]);
    expect(parseQueuePartition('')).toEqual([]);
  });

  it('should give each slot its group and every platform the queues of no group, once', () => {
    expect(partitionedPushQueues(connectors, groups, 0)).toEqual(['push_cve', 'push_rw', 'push_bg']);
    expect(partitionedPushQueues(connectors, groups, 1)).toEqual(['push_mitre', 'push_misp', 'push_bg']);
    expect(partitionedPushQueues(connectors, groups, null)).toEqual(['push_bg']);
  });

  it('should take the first free slot, keep it, and report it lost once its lock aborts', async () => {
    const controller = new AbortController();
    const tried: number[] = [];
    const slot = createPartitionSlot(2, async (i) => {
      tried.push(i);
      return i === 0 ? null : { signal: controller.signal, unlock: async () => {} };
    });
    expect(await slot.refresh()).toEqual(1);
    expect(await slot.refresh()).toEqual(1);
    expect(tried).toEqual([0, 1]);
    controller.abort();
    expect(await slot.refresh()).toBeNull();
    expect(slot.lost()).toBe(true);
  });

  it('should hold no slot when every slot is taken', async () => {
    const slot = createPartitionSlot(2, async () => null);
    expect(await slot.refresh()).toBeNull();
    expect(slot.lost()).toBe(false);
  });
});
