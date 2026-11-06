import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DraftLockedError, WorkNotALiveError } from '../../../src/config/errors';
import type { ChunkOperation } from '../../../src/graphql/chunk-executor';
import { describeOperation } from '../../../src/intake/dry-intake/simulated-answers';
import {
  createByteBudget,
  createLimiter,
  createQueueOrder,
  handlePushMessage,
  type PushIntakeDeps,
  type PushOperationOutcome,
  type PushOperationRun,
  PushRefusedError,
} from '../../../src/intake/workerless/push-intake';
import { createReleaseScheduler } from '../../../src/intake/workerless/release-scheduler';
import { createImportContext } from '../../../src/intake/stix-import/context';
import { RecordingClient } from '../import-conformance/import-conformance-client';
import { FIXTURES_DIR } from '../import-conformance/import-conformance-utils';
import { readFileSync } from 'node:fs';

// The worker-less intake: a push message decoded as the worker decodes it, transformed with its
// mutations captured, its operations released by the scheduler as their dependencies allow; the
// message answered once all its operations are terminal.

const malware = (index: number, extra: Record<string, unknown> = {}) => ({
  type: 'malware',
  spec_version: '2.1',
  id: `malware--00000000-0000-4000-8000-00000000000${index}`,
  created: '2024-01-01T00:00:00.000Z',
  modified: '2024-01-01T00:00:00.000Z',
  name: `Malware ${index}`,
  is_family: true,
  ...extra,
});
const author = { type: 'identity', spec_version: '2.1', id: 'identity--00000000-0000-4000-8000-0000000000a1', name: 'Author', identity_class: 'organization' };
const pushMessage = (content: unknown, envelope: Record<string, unknown> = {}) => ({
  type: 'bundle',
  applicant_id: 'applicant-1',
  work_id: 'work-1',
  content: Buffer.from(JSON.stringify(content)).toString('base64'),
  ...envelope,
});
const bundleOf = (...objects: unknown[]) => ({ type: 'bundle', id: 'bundle--00000000-0000-4000-8000-000000000000', objects });
const rootOf = (operation: ChunkOperation) => describeOperation(operation.query).root;

// A message run against the real scheduler; each operation's run is recorded and driven by `drive`
const intake = (options: {
  drive?: (run: PushOperationRun, events: string[]) => Promise<PushOperationOutcome>;
  reads?: () => any;
  writeContext?: PushIntakeDeps['writeContext'];
  fixtureDir?: string;
} = {}) => {
  const events: string[] = [];
  const runs: PushOperationRun[] = [];
  const reported: { key: string; outcomes: PushOperationOutcome[] }[] = [];
  const context = createImportContext(new RecordingClient(options.fixtureDir ?? FIXTURES_DIR, false), { error: () => {}, warn: () => {} });
  const deps: PushIntakeDeps = {
    scheduler: createReleaseScheduler({ queueDepth: () => 0, setPoint: () => 100 }),
    transformations: createLimiter(4),
    isTransient: (error) => error instanceof Error && error.message === 'engine overloaded',
    readsClient: options.reads ?? (() => new RecordingClient(options.fixtureDir ?? FIXTURES_DIR, false) as any),
    contextFor: () => context,
    writeContext: options.writeContext ?? (async () => ({ context: {} as any, user: {} as any })),
    runOperation: async (run) => {
      runs.push(run);
      events.push(`start ${rootOf(run.operation)}`);
      const outcome = options.drive ? await options.drive(run, events) : {};
      run.onQueued();
      events.push(`end ${rootOf(run.operation)}`);
      return outcome;
    },
    report: async (key, _context, _user, _envelope, _operations, outcomes) => {
      reported.push({ key, outcomes });
    },
  };
  return { deps, events, runs, reported };
};

describe('Worker-less push message', () => {
  it('should run the operations of a message under its envelope and ack it once all are terminal', async () => {
    const h = intake();
    const outcome = await handlePushMessage(pushMessage(bundleOf(malware(1), malware(2)), { draft_id: 'draft-1', event_id: 'event-1' }), 'queue-a', h.deps);
    expect(outcome).toEqual({ ack: true, reason: 'written', operations: 2, objects: 2 });
    expect(h.runs.map((run) => run.operation.object_id)).toEqual([malware(1).id, malware(2).id]);
    expect(h.runs[0].envelope).toMatchObject({ applicant_id: 'applicant-1', work_id: 'work-1', draft_id: 'draft-1', event_id: 'event-1', retry_number: 0 });
    expect(h.reported).toHaveLength(1);
  });

  it('should start an object once the author it references in the bundle is queued, not before', async () => {
    let queueAuthor: () => void = () => {};
    const authorQueued = new Promise<void>((resolve) => {
      queueAuthor = resolve;
    });
    const h = intake({
      drive: async (run, events) => {
        if (run.operation.object_id === author.id) {
          // the author is queued, then written later
          await authorQueued;
          events.push('author queued');
          run.onQueued();
        }
        return {};
      },
    });
    const handled = handlePushMessage(pushMessage(bundleOf(author, malware(1, { created_by_ref: author.id }))), 'queue-a', h.deps);
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    expect(h.events).toEqual(['start organizationAdd']);
    queueAuthor();
    expect(await handled).toMatchObject({ ack: true, reason: 'written' });
    expect(h.events.indexOf('author queued')).toBeLessThan(h.events.indexOf('start malwareAdd'));
    // the member mark is gone from what the platform executes only when the write context strips it:
    // here the stub does not, the ref still points to the author
    expect(JSON.stringify(h.runs[1].operation.variables)).toContain(author.id);
  });

  it('should give a producer that runs first its platform id in what waits for it', async () => {
    // pycti reads an external reference as a report: the reference and the report are created
    // first (echo ids), the report's id answered by the platform, then the malware is added to it
    const fixtureDir = join(FIXTURES_DIR, 'sdo/malware/handwritten-external-reference-as-report.legacy');
    const bundle = JSON.parse(readFileSync(join(fixtureDir, 'input.json'), 'utf-8'));
    const h = intake({
      fixtureDir,
      drive: async (run) => (rootOf(run.operation) === 'reportAdd' ? { id: 'report-platform-id' } : {}),
    });
    const call = JSON.parse(readFileSync(join(fixtureDir, 'call.json'), 'utf-8'));
    expect(await handlePushMessage(pushMessage(bundle, { entities_types: call.types }), 'queue-a', h.deps)).toMatchObject({ ack: true, reason: 'written' });
    const roots = h.runs.map((run) => rootOf(run.operation));
    const relationAdd = h.runs[roots.indexOf('reportEdit')];
    expect(relationAdd.operation.variables?.id).toEqual('report-platform-id');
    expect(roots.indexOf('reportEdit')).toBeGreaterThan(roots.indexOf('reportAdd'));
    // the external reference, a producer with a standard id, is referenced by it
    const report = h.runs[roots.indexOf('reportAdd')];
    expect(JSON.stringify(report.operation.variables)).toMatch(/external-reference--/);
    expect(h.runs.find((run) => rootOf(run.operation) === 'reportAdd')?.producerFirst).toBe(true);
  });

  it('should nack what the worker cannot decode or split, without running anything', async () => {
    const h = intake();
    expect(await handlePushMessage(null, 'q', h.deps)).toMatchObject({ ack: false, reason: 'undecodable' });
    expect(await handlePushMessage({ type: 'bundle', content: 42 }, 'q', h.deps)).toMatchObject({ ack: false, reason: 'undecodable' });
    expect(await handlePushMessage(pushMessage({ type: 'bundle', objects: [] }), 'q', h.deps)).toMatchObject({ ack: false, reason: 'undecodable' });
    // a defect of the transformation (here a read failing with a native error): nacked as the worker nacks
    const broken = intake({ reads: () => ({ query: async () => {
      throw new TypeError('defect');
    } }) });
    expect(await handlePushMessage(pushMessage(bundleOf(malware(1, { malware_types: ['ransomware'] }))), 'q', broken.deps)).toMatchObject({ ack: false, reason: 'transformation_failed' });
    expect([...h.runs, ...broken.runs]).toEqual([]);
  });

  it('should skip, acked, a message whose work is deleted or whose draft is closed, nack one whose writer is unknown', async () => {
    // an open vocabulary makes the transformation read: the read context is refused
    const withRead = bundleOf(malware(1, { malware_types: ['ransomware'] }));
    const refusing = (error: Error) => intake({ reads: () => ({ query: async () => {
      throw error;
    } }) }).deps;
    expect(await handlePushMessage(pushMessage(withRead), 'q', refusing(WorkNotALiveError()))).toMatchObject({ ack: true, reason: 'work_not_alive', operations: 0 });
    expect(await handlePushMessage(pushMessage(withRead), 'q', refusing(DraftLockedError()))).toMatchObject({ ack: true, reason: 'draft_locked', operations: 0 });
    // the write context refuses: same outcomes
    const writeRefusing = (reason: 'work_not_alive' | 'unknown_writer') => intake({ writeContext: async () => {
      throw new PushRefusedError('refused', reason);
    } });
    const unknown = writeRefusing('unknown_writer');
    expect(await handlePushMessage(pushMessage(bundleOf(malware(1))), 'q', unknown.deps)).toMatchObject({ ack: false, reason: 'unknown_writer' });
    expect(await handlePushMessage(pushMessage(bundleOf(malware(1))), 'q', writeRefusing('work_not_alive').deps)).toMatchObject({ ack: true, reason: 'work_not_alive' });
    expect(unknown.runs).toEqual([]);
  });
  it('should give back to its queue a message that met a transient failure before any write', async () => {
    const h = intake({ writeContext: async () => {
      throw new Error('engine overloaded');
    } });
    expect(await handlePushMessage(pushMessage(bundleOf(malware(1))), 'q', h.deps)).toMatchObject({ ack: false, requeue: true, reason: 'transient' });
    expect(h.runs).toEqual([]);
    // any other failure of the write context is not retried
    const broken = intake({ writeContext: async () => {
      throw new Error('defect');
    } });
    await expect(handlePushMessage(pushMessage(bundleOf(malware(1))), 'q', broken.deps)).rejects.toThrow('defect');
  });
});

describe('Worker-less intake flow control', () => {
  it('should run at most the limit at once, the others in turn', async () => {
    const limiter = createLimiter(2);
    const releases: (() => void)[] = [];
    const started: number[] = [];
    const runs = [0, 1, 2, 3].map((index) => limiter.run(() => new Promise<void>((resolve) => {
      started.push(index);
      releases[index] = resolve;
    })));
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    expect(started).toEqual([0, 1]);
    releases[1]();
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    expect(started).toEqual([0, 1, 2]);
    releases[0]();
    releases[2]();
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
    releases[3]();
    await Promise.all(runs);
    expect(started).toEqual([0, 1, 2, 3]);
    expect(limiter.running()).toEqual(0);
  });

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
