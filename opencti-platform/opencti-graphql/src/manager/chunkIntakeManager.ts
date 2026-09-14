// POC chunk-queue direct intake (kb note opencti-chunk-queue-direct-intake-design).
// The worker's queue_thread splits the bundle, builds chunks and maps each object to its
// GraphQL ingestion mutation (pycti capture transport), then publishes ONE message per CHUNK.
// This manager is the platform-side consumer: a lock-elected singleton (the managerModule cron
// lock) that strips the ||M|| member marks, executes the chunk's operations in process
// (graphql.execute, no HTTP) and acks the chunk only once every operation reached a terminal
// state, which for sequencer-eligible writes means AFTER the batch commit.
//
// Flow control is a single valve: rabbit prefetch x chunk size = the intents offered to the
// sequencer loop, replacing the worker-side pf / chunk-size / http-pool / queue_max_intents
// quadruple that drove every feeding artifact measured on the HTTP topology.
import { ValueType } from '@opentelemetry/api';
import type { Counter, Histogram } from '@opentelemetry/api';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { meterManager } from '../config/tracing';
import { executionContext, isUserInPlatformOrganization, SYSTEM_USER } from '../utils/access';
import { chunkIntakeQueue, consumeChunkIntakeQueue, registerChunkIntakeQueue } from '../database/rabbitmq';
import { executeChunkOperation, substituteEchoIds, type ChunkOperation } from '../graphql/chunk-executor';
import { stripMemberRefMarks } from '../database/sequencer/sequencer-eligibility';
import { registerPendingIntentSettled } from '../database/sequencer/sequencer-pending-intents';
import { SEQUENCER_DEFERRED_ERROR } from '../config/errors';
import { authenticateUserByUserId, userWithOrigin } from '../domain/user';
import { computeLoaders } from '../http/httpAuthenticatedContext';
import { reportExpectation } from '../domain/work';
import { getEntityFromCache } from '../database/cache';
import { wait } from '../database/utils';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreSettings } from '../types/settings';

const CHUNK_INTAKE_MANAGER_ID = 'CHUNK_INTAKE_MANAGER';
const CHUNK_INTAKE_MANAGER_CONTEXT = 'chunk_intake_manager';

const CHUNK_INTAKE_MANAGER_ENABLED = booleanConf('chunk_intake_manager:enabled', false);
const CHUNK_INTAKE_MANAGER_KEY = conf.get('chunk_intake_manager:lock_key') || 'chunk_intake_manager_lock';
const SCHEDULE_TIME = Number(conf.get('chunk_intake_manager:interval') ?? 10000);
const PREFETCH = Number(conf.get('chunk_intake_manager:prefetch') ?? 8);
const MAX_TRANSIENT_ATTEMPTS = Number(conf.get('chunk_intake_manager:max_transient_attempts') ?? 20);
// Retry-gap option 1: a creation whose hard reference is still missing after its park
// deadline is RETAINED by the sequencer (pending intents) and re-submitted when the
// reference lands, instead of failing into a client retry ladder that this path removed.
const DEFER_MISSING_REFS = booleanConf('chunk_intake_manager:defer_missing_refs', true);

// Chunk-level failure policy. A chunk fails as a whole for two very different reasons that
// must not share a fate. STRUCTURAL (poison): the failure is a property of the message
// itself (unparsable, no operations, a writer that no longer exists) and every redelivery
// would fail identically, so the chunk goes to the dead-letter queue at once. TRANSIENT:
// anything else (ES or redis unavailable, lock timeout, restart mid-chunk) is requeued,
// never dead-lettered: a thirty-second outage must not cost data. Requeues are bounded
// (attempt count per chunk, exponential backoff while HOLDING the prefetch slot, which
// doubles as backpressure during the outage) so a misclassified failure cannot loop
// forever: past the cap the chunk is dead-lettered loudly. Per-object failures never reach
// this policy: the sequencer parks, defers and reports them, and the chunk is acked.
export class ChunkPoisonError extends Error {
  readonly reason: string;

  constructor(message: string, reason: string) {
    super(message);
    this.name = 'ChunkPoisonError';
    this.reason = reason;
  }
}

// Attempts of currently failing chunks only: cleared on ack or dead-letter, so the map
// stays tiny (memory-only: a restart resets the count, the cap still bounds the total).
const transientAttempts = new Map<string, number>();

interface ChunkMessage {
  v?: number;
  chunk_id?: string;
  user_id?: string;
  applicant_id?: string;
  work_id?: string;
  draft_id?: string;
  retry_number?: number;
  operations?: ChunkOperation[];
}

interface ChunkControls {
  redelivered: boolean;
  ack: () => void;
  retry: () => void;
  deadLetter: () => void;
}

interface ChunkConsumer {
  queue: string;
  alive: () => boolean;
  close: () => Promise<void>;
}

// region metrics
let chunksCounter: Counter | null = null;
let operationsCounter: Counter | null = null;
let objectsCounter: Counter | null = null;
let chunkSeconds: Histogram | null = null;

const registerChunkMetrics = () => {
  if (chunksCounter) {
    return;
  }
  const meter = meterManager.meterProvider.getMeter('opencti-chunk-intake');
  chunksCounter = meter.createCounter('opencti_chunk_intake_chunks_total', {
    valueType: ValueType.INT,
    description: 'Chunk messages by outcome (acked, retried, dead_letter)',
  });
  operationsCounter = meter.createCounter('opencti_chunk_intake_operations_total', {
    valueType: ValueType.INT,
    description: 'Chunk operations by outcome (ok, error)',
  });
  // Objects, not operations: pycti emits several mutations for one STIX object (its labels,
  // external references and kill chain phases are separate creates), so the throughput KPI
  // needs the distinct object count per chunk.
  objectsCounter = meter.createCounter('opencti_chunk_intake_objects_total', {
    valueType: ValueType.INT,
    description: 'Distinct STIX objects carried by executed chunks',
  });
  chunkSeconds = meter.createHistogram('opencti_chunk_intake_chunk_seconds', {
    valueType: ValueType.DOUBLE,
    description: 'Wall time from chunk delivery to chunk ack',
  });
};
// endregion

// Builds the execution context a chunk runs under. Deliberately mirrors the HTTP one
// (httpAuthenticatedContext) field for field, minus everything request-shaped: same user
// resolution, same member-mark strip over the whole chunk, same batch loaders.
export const createChunkContext = async (message: ChunkMessage, operations: ChunkOperation[]) => {
  const context = executionContext(CHUNK_INTAKE_MANAGER_CONTEXT) as any;
  // Worker origin (sequencer eligibility) is carried by the retry-number header: presence is
  // what counts, "0" is the legitimate first attempt.
  const req: any = {
    headers: {
      'opencti-retry-number': String(message.retry_number ?? 0),
      ...(message.work_id ? { 'opencti-work-id': message.work_id } : {}),
      ...(message.draft_id ? { 'opencti-draft-id': message.draft_id } : {}),
    },
    ip: 'chunk-intake',
    header: () => undefined,
  };
  context.req = req;
  context.workId = message.work_id;
  context.draft_context = message.draft_id;
  context.deferMissingRefs = DEFER_MISSING_REFS;
  // ||M|| marks are transport-only: strip them for the WHOLE chunk before any coercion or
  // resolution, exactly as the HTTP edge does for a batched body. The union rides the context
  // to the sequencer boundary, where it classifies a missing ref as an in-chunk member.
  const memberRefs = new Set<string>();
  operations.forEach((operation) => {
    if (operation?.variables) stripMemberRefMarks(operation.variables, memberRefs);
  });
  if (memberRefs.size > 0) {
    context.memberRefIds = memberRefs;
  }
  // The message names the writer (the worker's own user, or the applicant it impersonates):
  // no token ever travels through the queue.
  const userId = message.applicant_id || message.user_id;
  let user: AuthUser;
  try {
    user = userId ? await authenticateUserByUserId(context, req, userId) : userWithOrigin(req, SYSTEM_USER);
  } catch (e: any) {
    // The writer named by the message is gone or invalid: no redelivery can change that.
    throw new ChunkPoisonError(`Chunk writer cannot be resolved (${userId}): ${e.message}`, 'unknown_writer');
  }
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  context.user = user;
  context.user_otp_validated = true;
  context.user_with_session = false;
  context.user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
  context.batch = computeLoaders(context, user);
  return { context: context as AuthContext, user };
};

// Outcome of one operation: ok, failed with an error, or RETAINED by the sequencer (its hard
// reference is still missing: the creation is stored and re-submitted when the reference
// lands, so it is neither an error nor a completion yet).
interface OperationOutcome {
  error?: string;
  deferred?: boolean;
}

const reportChunkOutcome = async (
  context: AuthContext,
  user: AuthUser,
  message: ChunkMessage,
  operation: ChunkOperation,
  outcome: OperationOutcome,
) => {
  if (outcome.deferred) {
    // the work expectation stays open: the pending intents store reports it when the
    // creation lands or expires (registerPendingIntentSettled below)
    operationsCounter?.add(1, { outcome: 'deferred' });
    return;
  }
  if (outcome.error) {
    logApp.error('[CHUNK-INTAKE] Operation failed', { chunk_id: message.chunk_id, object_id: operation.object_id, error: outcome.error });
  }
  operationsCounter?.add(1, { outcome: outcome.error ? 'error' : 'ok' });
  // Work bookkeeping is now in process: pycti called reportExpectation over HTTP for EVERY
  // object (success included), which was the second HTTP call per object on the old path.
  if (message.work_id) {
    await reportExpectation(context, user, message.work_id, outcome.error ? { error: outcome.error, source: 'chunk intake' } : undefined);
  }
};

export const processChunkMessage = async (payload: string, controls: ChunkControls) => {
  const start = Date.now();
  let message: ChunkMessage;
  try {
    message = JSON.parse(payload);
  } catch (e: any) {
    logApp.error('[CHUNK-INTAKE] Unparsable chunk message, dead lettering', { cause: e });
    chunksCounter?.add(1, { outcome: 'dead_letter', reason: 'unparsable' });
    controls.deadLetter();
    return;
  }
  const operations = Array.isArray(message.operations) ? message.operations : [];
  if (operations.length === 0) {
    logApp.error('[CHUNK-INTAKE] Chunk without operations, dead lettering', { chunk_id: message.chunk_id });
    chunksCounter?.add(1, { outcome: 'dead_letter', reason: 'empty' });
    controls.deadLetter();
    return;
  }
  // A chunk without an id (hand-published) is keyed by its payload head: same policy.
  const attemptKey = message.chunk_id ?? payload.slice(0, 128);
  try {
    const { context, user } = await createChunkContext(message, operations);
    // Two phases. pycti pre-creates an object's labels, external references and kill
    // chain phases through separate mutations and puts the ids the platform RETURNED into
    // the object's input; on the capture transport those creates answered with echo ids,
    // so their operations (the producers) run first and the real ids replace the echo ids
    // in the remaining operations. Within a phase everything is in flight at once, like an
    // HTTP-batched body: ordering inside the chunk is the sequencer's business.
    const resolved = new Map<string, string>();
    const runOperation = async (operation: ChunkOperation): Promise<OperationOutcome> => {
      try {
        const result = await executeChunkOperation(context, operation);
        if (result.errors?.length) {
          const first: any = result.errors[0];
          if (first?.extensions?.code === SEQUENCER_DEFERRED_ERROR) {
            return { deferred: true };
          }
          return { error: String(first.message) };
        }
        if (operation.echo_id) {
          const root: any = result.data ? Object.values(result.data)[0] : undefined;
          if (root?.id) resolved.set(operation.echo_id, String(root.id));
        }
        return {};
      } catch (e: any) {
        return { error: String(e.message ?? e) };
      }
    };
    const producers = operations.filter((operation) => operation.echo_id);
    const consumers = operations.filter((operation) => !operation.echo_id);
    const producerErrors = await Promise.all(producers.map(runOperation));
    if (resolved.size > 0) {
      consumers.forEach((operation) => {
        if (operation.variables) substituteEchoIds(operation.variables, resolved);
      });
    }
    const consumerErrors = await Promise.all(consumers.map(runOperation));
    const ordered = [...producers, ...consumers];
    const results = [...producerErrors, ...consumerErrors];
    for (let index = 0; index < ordered.length; index += 1) {
      await reportChunkOutcome(context, user, message, ordered[index], results[index]);
    }
    controls.ack();
    transientAttempts.delete(attemptKey);
    chunksCounter?.add(1, { outcome: 'acked' });
    objectsCounter?.add(new Set(operations.map((operation) => operation.object_id).filter((id) => !!id)).size);
    chunkSeconds?.record((Date.now() - start) / 1000);
  } catch (e: any) {
    if (e instanceof ChunkPoisonError) {
      logApp.error('[CHUNK-INTAKE] Poison chunk, dead lettering', { cause: e, chunk_id: message.chunk_id, reason: e.reason });
      chunksCounter?.add(1, { outcome: 'dead_letter', reason: e.reason });
      transientAttempts.delete(attemptKey);
      controls.deadLetter();
      return;
    }
    const attempts = (transientAttempts.get(attemptKey) ?? 0) + 1;
    if (attempts > MAX_TRANSIENT_ATTEMPTS) {
      logApp.error('[CHUNK-INTAKE] Chunk failed past the transient retry cap, dead lettering', { cause: e, chunk_id: message.chunk_id, attempts });
      chunksCounter?.add(1, { outcome: 'dead_letter', reason: 'transient_cap' });
      transientAttempts.delete(attemptKey);
      controls.deadLetter();
      return;
    }
    transientAttempts.set(attemptKey, attempts);
    const backoffMs = Math.min(1000 * 2 ** (attempts - 1), 30000);
    logApp.warn('[CHUNK-INTAKE] Chunk failed, requeueing after backoff', { cause: e, chunk_id: message.chunk_id, attempts, backoffMs, redelivered: controls.redelivered });
    chunksCounter?.add(1, { outcome: 'retried' });
    await wait(backoffMs);
    controls.retry();
  }
};

const chunkIntakeInitializer = async () => {
  registerChunkMetrics();
  // Terminal outcome of a retained creation: meet the work expectation the chunk skipped
  // (applied), or meet it with an error (expired / failed), so works stay exact.
  registerPendingIntentSettled(async (record, error) => {
    if (!record.work_id) return;
    const settleContext = executionContext(CHUNK_INTAKE_MANAGER_CONTEXT);
    await reportExpectation(settleContext, SYSTEM_USER, record.work_id, error ? { error, source: 'chunk intake (retained creation)' } : undefined);
  });
  await registerChunkIntakeQueue();
  const consumer: ChunkConsumer = await consumeChunkIntakeQueue(PREFETCH, (payload: string, controls: ChunkControls) => {
    processChunkMessage(payload, controls).catch((e) => {
      logApp.error('[CHUNK-INTAKE] Unexpected chunk handling error', { cause: e });
    });
  });
  logApp.info('[OPENCTI-MODULE] Chunk intake manager consuming', { queue: consumer.queue, prefetch: PREFETCH });
  return {
    consumer,
    shutdown: async () => {
      await consumer.close();
      logApp.info('[OPENCTI-MODULE] Chunk intake consumer closed');
    },
  };
};

// The consumer lives in its own connection: this tick only holds the singleton lock and
// surfaces a lost consumer, which ends the handler loop so the next cron re-elects and
// reconnects.
export const chunkIntakeHandler = async (cronInput?: any) => {
  if (cronInput?.consumer && !cronInput.consumer.alive()) {
    throw new Error('Chunk intake consumer is not alive');
  }
};

const CHUNK_INTAKE_MANAGER_DEFINITION: ManagerDefinition = {
  id: CHUNK_INTAKE_MANAGER_ID,
  label: 'Chunk intake manager',
  executionContext: CHUNK_INTAKE_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: chunkIntakeHandler,
    handlerInitializer: chunkIntakeInitializer,
    interval: SCHEDULE_TIME,
    infiniteInterval: SCHEDULE_TIME,
    lockKey: CHUNK_INTAKE_MANAGER_KEY,
  },
  enabledByConfig: CHUNK_INTAKE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(CHUNK_INTAKE_MANAGER_DEFINITION);

export { chunkIntakeQueue };
