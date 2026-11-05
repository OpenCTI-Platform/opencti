import { describe, expect, it, vi } from 'vitest';
import { DraftLockedError, WorkNotALiveError } from '../../../src/config/errors';
import { createByteBudget, createQueueOrder, handlePushMessage, type PushChunk, type PushIntakeDeps } from '../../../src/intake/workerless/push-intake';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { RecordingClient } from '../import-conformance/import-conformance-client';
import { FIXTURES_DIR } from '../import-conformance/import-conformance-utils';

// The worker-less intake: a push message decoded as the worker decodes it, transformed with its
// mutations captured, its chunks run in process; the message answered once all its chunks are.

const malware = (index: number) => ({
  type: 'malware',
  spec_version: '2.1',
  id: `malware--00000000-0000-4000-8000-00000000000${index}`,
  created: '2024-01-01T00:00:00.000Z',
  modified: '2024-01-01T00:00:00.000Z',
  name: `Malware ${index}`,
  is_family: true,
});
const pushMessage = (content: unknown, envelope: Record<string, unknown> = {}) => ({
  type: 'bundle',
  applicant_id: 'applicant-1',
  work_id: 'work-1',
  content: Buffer.from(JSON.stringify(content)).toString('base64'),
  ...envelope,
});
const bundleOf = (...objects: unknown[]) => ({ type: 'bundle', id: 'bundle--00000000-0000-4000-8000-000000000000', objects });

const depsWith = (runChunk: PushIntakeDeps['runChunk'], reads = () => new RecordingClient(FIXTURES_DIR, false) as any): PushIntakeDeps => {
  const context = createImportContext(new RecordingClient(FIXTURES_DIR, false), { error: () => {}, warn: () => {} });
  return { runChunk, readsClient: reads, contextFor: () => context, chunkSize: 1 };
};

describe('Worker-less push message', () => {
  it('should run the chunks of a message under its envelope and ack it once all are written', async () => {
    const chunks: PushChunk[] = [];
    const outcome = await handlePushMessage(pushMessage(bundleOf(malware(1), malware(2)), { draft_id: 'draft-1', event_id: 'event-1' }), depsWith(async (chunk) => {
      chunks.push(chunk);
      return 'acked';
    }));
    expect(outcome).toEqual({ ack: true, reason: 'written', chunks: 2, objects: 2 });
    expect(chunks.map((chunk) => chunk.operations.map((operation) => operation.object_id))).toEqual([[malware(1).id], [malware(2).id]]);
    expect(chunks[0]).toMatchObject({ applicant_id: 'applicant-1', work_id: 'work-1', draft_id: 'draft-1', event_id: 'event-1', retry_number: 0, work_objects: 1 });
    expect(new Set(chunks.map((chunk) => chunk.chunk_id)).size).toEqual(2);
  });

  it('should nack a message one of whose chunks is dead-lettered, after all its chunks ran', async () => {
    const run = vi.fn().mockResolvedValueOnce('acked').mockResolvedValueOnce('dead_lettered');
    const outcome = await handlePushMessage(pushMessage(bundleOf(malware(1), malware(2))), depsWith(run));
    expect(outcome).toMatchObject({ ack: false, reason: 'chunk_dead_lettered', chunks: 2 });
    expect(run).toHaveBeenCalledTimes(2);
  });

  it('should nack what the worker cannot decode or split, without running anything', async () => {
    const run = vi.fn();
    expect(await handlePushMessage(null, depsWith(run))).toMatchObject({ ack: false, reason: 'undecodable' });
    expect(await handlePushMessage({ type: 'bundle', content: 42 }, depsWith(run))).toMatchObject({ ack: false, reason: 'undecodable' });
    expect(await handlePushMessage(pushMessage({ type: 'bundle', objects: [] }), depsWith(run))).toMatchObject({ ack: false, reason: 'undecodable' });
    // a defect of the transformation (here a read failing with a native error): nacked as the worker nacks
    const broken = () => ({ query: async () => {
      throw new TypeError('defect');
    } });
    expect(await handlePushMessage(pushMessage(bundleOf({ ...malware(1), malware_types: ['ransomware'] })), depsWith(run, broken))).toMatchObject({ ack: false, reason: 'transformation_failed' });
    expect(run).not.toHaveBeenCalled();
  });

  it('should skip, acked, a message whose work is deleted or whose draft is closed when it reads', async () => {
    // an open vocabulary makes the transformation read: the read context is refused
    const withRead = bundleOf({ ...malware(1), malware_types: ['ransomware'] });
    const refusing = (error: Error) => () => ({ query: async () => {
      throw error;
    } });
    expect(await handlePushMessage(pushMessage(withRead), depsWith(vi.fn(), refusing(WorkNotALiveError())))).toMatchObject({ ack: true, reason: 'work_not_alive', chunks: 0 });
    expect(await handlePushMessage(pushMessage(withRead), depsWith(vi.fn(), refusing(DraftLockedError())))).toMatchObject({ ack: true, reason: 'draft_locked', chunks: 0 });
  });
});

describe('Worker-less intake flow control', () => {
  it('should start a message once the bytes in flight leave room for it, alone always', async () => {
    const budget = createByteBudget(100);
    await budget.acquire(80);
    let second = false;
    const waiting = budget.acquire(50).then(() => {
      second = true;
    });
    await Promise.resolve();
    expect(second).toBe(false);
    budget.release(80);
    await waiting;
    expect(budget.inFlight()).toEqual(50);
    budget.release(50);
    // larger than the budget, alone: it starts
    await budget.acquire(500);
    expect(budget.inFlight()).toEqual(500);
  });

  it('should run the messages of an event queue one at a time, in order, other queues concurrently', async () => {
    const order = createQueueOrder();
    const events: string[] = [];
    const gate = (name: string) => {
      let release: () => void = () => {};
      const done = new Promise<void>((resolve) => {
        release = resolve;
      });
      return { name, release, run: async () => {
        events.push(`start ${name}`);
        await done;
        events.push(`end ${name}`);
      } };
    };
    const bundle = gate('bundle');
    const create = gate('create');
    const remove = gate('delete');
    const other = gate('other queue');
    const runs = [
      order.schedule('sync', false, bundle.run),
      order.schedule('sync', true, create.run),
      order.schedule('sync', true, remove.run),
      order.schedule('feed', false, other.run),
    ];
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    // the first event waits for the message already running in its queue; another queue runs
    expect(events).toEqual(['start bundle', 'start other queue']);
    bundle.release();
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    expect(events).toEqual(['start bundle', 'start other queue', 'end bundle', 'start create']);
    remove.release();
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    // the delete does not start before the create is written
    expect(events).not.toContain('start delete');
    create.release();
    other.release();
    await Promise.all(runs);
    expect(events.indexOf('end create')).toBeLessThan(events.indexOf('start delete'));
    expect(order.isOrdered('sync')).toBe(true);
    expect(order.isOrdered('feed')).toBe(false);
  });
});
