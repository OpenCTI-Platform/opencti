import { randomUUID } from 'node:crypto';
import { DRAFT_LOCKED_ERROR, WORK_NOT_ALIVE_ERROR } from '../../config/errors';
import { type ChunkOperation, substituteEchoIds } from '../../graphql/chunk-executor';
import { intentSourceOf } from '../../database/sequencer/sequencer-intent';
import { resolveProducerIds } from '../../manager/chunkIntakeProducers';
import type { AuthContext, AuthUser } from '../../types/user';
import { captureOperations } from '../chunk-capture/capture-bundle';
import { bundleOf, decodeData } from '../dry-intake/dry-intake-message';
import { type IntakeEnvelope, intakeEnvelopeOfMessage } from '../intake-envelope';
import type { ImportContext } from '../stix-import/context';
import type { ImportClient } from '../stix-import/types';
import { buildOperationGraph } from './operation-graph';
import type { ReleaseScheduler } from './release-scheduler';

// The worker-less intake (POC): the platform consumes the connector push queues in place of the
// workers. A push message is decoded as the worker decodes it, its bundle transformed with the
// mutations captured (chunk-capture), and its operations admitted to the release scheduler as a
// dependency graph (KB note opencti-workerless-intake-target-design): each operation runs once
// what it depends on is queued or written and the sequencer has room. The message is answered once
// every operation is terminal: acked (written, failed and reported, or retained), nacked (not
// requeued) when it cannot be decoded or transformed or its writer is unknown, as the worker nacks.

// How an operation ended (the chunk intake manager's runIntakeOperation)
export interface PushOperationOutcome {
  error?: string;
  deferred?: boolean;
  // The id the platform gave a producer whose id is substituted
  id?: string;
}

// One operation to run, under the write context of its message
export interface PushOperationRun {
  key: string;
  context: AuthContext;
  user: AuthUser;
  envelope: IntakeEnvelope;
  operation: ChunkOperation;
  producerFirst: boolean;
  onQueued: () => void;
}

// A message whose writes the platform refuses before they run, as the HTTP edge refuses the worker
export class PushRefusedError extends Error {
  readonly reason: PushReason;

  constructor(message: string, reason: PushReason) {
    super(message);
    this.reason = reason;
  }
}

export interface PushIntakeDeps {
  scheduler: ReleaseScheduler;
  // Bounds the transformations running at once: their reads reach the engine outside the
  // pre-loop gate, and the prefetch holds many messages
  transformations: Limiter;
  // An error that a later attempt may not meet (engine overloaded or unreachable)
  isTransient: (error: unknown) => boolean;
  // The transformation's reads for a message, run in process under its context
  readsClient: (envelope: IntakeEnvelope) => ImportClient;
  // The transformation context of a draft, kept for the life of the intake (pycti's caches)
  contextFor: (draftId: string) => ImportContext;
  // The write context of a message (intake context rules), its member marks stripped from the
  // operations; throws PushRefusedError
  writeContext: (envelope: IntakeEnvelope, operations: ChunkOperation[], memberIds: Iterable<string>) => Promise<{ context: AuthContext; user: AuthUser }>;
  // Runs one operation to its end
  runOperation: (run: PushOperationRun) => Promise<PushOperationOutcome>;
  // The operations' outcomes, once all are terminal (metrics, work)
  report: (key: string, context: AuthContext, user: AuthUser, envelope: IntakeEnvelope, operations: ChunkOperation[], outcomes: PushOperationOutcome[]) => Promise<void>;
}

export type PushReason = 'written' | 'undecodable' | 'transformation_failed' | 'transient' | 'unknown_writer' | 'work_not_alive' | 'draft_locked';

export interface PushOutcome {
  ack: boolean;
  // Not acked, given back to its queue to run again (a transient failure before any write)
  requeue?: boolean;
  reason: PushReason;
  operations: number;
  objects: number;
}

// The push message, parsed: the intake reads its type before handling it (an event queue is consumed in order)
export const parsePushMessage = (body: string): Record<string, any> | null => {
  try {
    const data = JSON.parse(body);
    return data !== null && typeof data === 'object' ? data : null;
  } catch {
    return null;
  }
};

export const isEventMessage = (data: Record<string, any>) => data.type === 'event';

const refusalOf = (error: any): PushReason | null => {
  if (error instanceof PushRefusedError) return error.reason;
  const code = error?.extensions?.code;
  if (code === WORK_NOT_ALIVE_ERROR) return 'work_not_alive';
  if (code === DRAFT_LOCKED_ERROR) return 'draft_locked';
  return null;
};

// At most `limit` runs at once, the others wait their turn in order
export const createLimiter = (limit: number) => {
  let running = 0;
  const waiting: (() => void)[] = [];
  return {
    run: async <T>(fn: () => Promise<T>): Promise<T> => {
      if (running < limit) {
        running += 1;
      } else {
        // the slot is handed over by the run that ends
        await new Promise<void>((resolve) => {
          waiting.push(resolve);
        });
      }
      try {
        return await fn();
      } finally {
        const next = waiting.shift();
        if (next) next();
        else running -= 1;
      }
    },
    running: () => running,
    waiting: () => waiting.length,
  };
};
export type Limiter = ReturnType<typeof createLimiter>;

const transient = (objects: number): PushOutcome => ({ ack: false, requeue: true, reason: 'transient', operations: 0, objects });

// A refused message is skipped as the worker skips it (acked: a deleted work, a closed draft), or
// nacked when no redelivery can make it run (an unknown writer)
const refused = (reason: PushReason, objects: number): PushOutcome => ({ ack: reason !== 'unknown_writer', reason, operations: 0, objects });

export const handlePushMessage = async (data: Record<string, any> | null, queue: string, deps: PushIntakeDeps): Promise<PushOutcome> => {
  if (!data) {
    return { ack: false, reason: 'undecodable', operations: 0, objects: 0 };
  }
  let decoded: ReturnType<typeof decodeData>;
  let bundle: Record<string, any>;
  let update: boolean;
  try {
    decoded = decodeData(data);
    ({ bundle, update } = bundleOf(decoded));
  } catch {
    return { ack: false, reason: 'undecodable', operations: 0, objects: 0 };
  }
  const objects = Array.isArray(bundle.objects) ? bundle.objects.length : 0;
  // The worker sends retry number 0 on the first attempt: worker origin (sequencer eligibility)
  const envelope: IntakeEnvelope = { ...intakeEnvelopeOfMessage(data), retry_number: 0 };
  let operations: ChunkOperation[];
  try {
    const context = { ...deps.contextFor(decoded.draftId), client: deps.readsClient(envelope) };
    ({ operations } = await deps.transformations.run(() => captureOperations(context, bundle, update, decoded.types)));
  } catch (error: any) {
    // A read of the transformation refused by the context checks (the HTTP edge's)
    const reason = refusalOf(error);
    if (reason) return refused(reason, objects);
    // Nothing written yet: run it again later (a read failing on a GraphQL error is an outcome of
    // its object, as pycti's ValueError, and never reaches here)
    if (deps.isTransient(error)) return transient(objects);
    // The split fails (a malformed message) or the transformation has a defect: the worker nacks
    return { ack: false, reason: 'transformation_failed', operations: 0, objects };
  }
  // The graph is read from the operations as captured (echo ids, ||M|| marks), before the producer
  // ids are substituted and the marks stripped
  const graph = buildOperationGraph(operations);
  // Producers with a standard id computable from their input (labels, external references...):
  // their consumers carry it and only need them queued. The others run first: their consumers wait
  // for the id the platform gives them.
  const { resolved, unresolved } = resolveProducerIds(operations);
  const answerNeeded = new Set(unresolved);
  if (resolved.size > 0) {
    operations.forEach((operation) => {
      if (operation.variables) substituteEchoIds(operation.variables, resolved);
    });
  }
  let written: { context: AuthContext; user: AuthUser };
  try {
    written = await deps.writeContext(envelope, operations, resolved.values());
  } catch (error: any) {
    const reason = refusalOf(error);
    if (reason) return refused(reason, objects);
    if (deps.isTransient(error)) return transient(objects);
    throw error;
  }
  const { context, user } = written;
  const key = randomUUID();
  const outcomes = await deps.scheduler.admit<PushOperationOutcome>({
    source: queue,
    lane: intentSourceOf(user),
    nodes: graph.nodes.map(({ operation, kind, deps: operationDeps, creates, external }) => ({
      kind, deps: operationDeps, creates, external, answerNeeded: answerNeeded.has(operation),
    })),
    run: async (index, hooks) => {
      const operation = operations[index];
      // the ids of the producers it waited for, once they ran
      if (operation.variables && resolved.size > 0) substituteEchoIds(operation.variables, resolved);
      const outcome = await deps.runOperation({ key, context, user, envelope, operation, producerFirst: answerNeeded.has(operation), onQueued: hooks.queued });
      if (operation.echo_id && outcome.id) resolved.set(operation.echo_id, outcome.id);
      return outcome;
    },
  });
  await deps.report(key, context, user, envelope, operations, outcomes);
  return { ack: true, reason: 'written', operations: operations.length, objects };
};

// The bytes of the messages in flight: a message starts once the budget has room for it (alone, it
// always starts). The decoded bundle, its objects, the captured operations and the files are held
// several times over the size of the message: a message count does not bound the memory.
export const createByteBudget = (maxBytes: number) => {
  let inFlight = 0;
  const waiting: { bytes: number; start: () => void }[] = [];
  const startWaiting = () => {
    while (waiting.length > 0 && (inFlight === 0 || inFlight + waiting[0].bytes <= maxBytes)) {
      const next = waiting.shift() as (typeof waiting)[number];
      inFlight += next.bytes;
      next.start();
    }
  };
  return {
    acquire: (bytes: number) => new Promise<void>((resolve) => {
      waiting.push({ bytes, start: resolve });
      startWaiting();
    }),
    release: (bytes: number) => {
      inFlight -= bytes;
      startWaiting();
    },
    inFlight: () => inFlight,
    waiting: () => waiting.length,
  };
};

// The order of a queue: the messages of a queue that carries stream events (create, update, delete,
// merge of the same entities) run one at a time, each once the previous one is written, as a single
// worker consumes a queue (prefetch 1, ack after the write). Other queues run their messages
// concurrently. A queue turns ordered with its first event, after the messages already running.
export const createQueueOrder = () => {
  const ordered = new Map<string, Promise<void>>();
  const running = new Map<string, Set<Promise<void>>>();
  const track = (queue: string, run: Promise<void>) => {
    let set = running.get(queue);
    if (!set) {
      set = new Set();
      running.set(queue, set);
    }
    set.add(run);
    run.finally(() => set?.delete(run)).catch(() => {});
    return run;
  };
  return {
    schedule: (queue: string, isEvent: boolean, handle: () => Promise<void>): Promise<void> => {
      if (isEvent && !ordered.has(queue)) {
        ordered.set(queue, Promise.all([...(running.get(queue) ?? [])]).then(() => undefined, () => undefined));
      }
      const tail = ordered.get(queue);
      if (!tail) {
        return track(queue, handle());
      }
      const next = tail.then(handle);
      ordered.set(queue, next.then(() => undefined, () => undefined));
      return track(queue, next);
    },
    isOrdered: (queue: string) => ordered.has(queue),
  };
};
