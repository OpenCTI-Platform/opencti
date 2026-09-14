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
import { executeChunkOperation, type ChunkOperation } from '../graphql/chunk-executor';
import { stripMemberRefMarks } from '../database/sequencer/sequencer-eligibility';
import { authenticateUserByUserId, userWithOrigin } from '../domain/user';
import { computeLoaders } from '../http/httpAuthenticatedContext';
import { reportExpectation } from '../domain/work';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreSettings } from '../types/settings';

const CHUNK_INTAKE_MANAGER_ID = 'CHUNK_INTAKE_MANAGER';
const CHUNK_INTAKE_MANAGER_CONTEXT = 'chunk_intake_manager';

const CHUNK_INTAKE_MANAGER_ENABLED = booleanConf('chunk_intake_manager:enabled', false);
const CHUNK_INTAKE_MANAGER_KEY = conf.get('chunk_intake_manager:lock_key') || 'chunk_intake_manager_lock';
const SCHEDULE_TIME = Number(conf.get('chunk_intake_manager:interval') ?? 10000);
const PREFETCH = Number(conf.get('chunk_intake_manager:prefetch') ?? 8);

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
  const user: AuthUser = userId
    ? await authenticateUserByUserId(context, req, userId)
    : userWithOrigin(req, SYSTEM_USER);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  context.user = user;
  context.user_otp_validated = true;
  context.user_with_session = false;
  context.user_inside_platform_organization = isUserInPlatformOrganization(user, settings);
  context.batch = computeLoaders(context, user);
  return { context: context as AuthContext, user };
};

const reportChunkOutcome = async (
  context: AuthContext,
  user: AuthUser,
  message: ChunkMessage,
  operation: ChunkOperation,
  error?: string,
) => {
  if (error) {
    logApp.error('[CHUNK-INTAKE] Operation failed', { chunk_id: message.chunk_id, object_id: operation.object_id, error });
  }
  operationsCounter?.add(1, { outcome: error ? 'error' : 'ok' });
  // Work bookkeeping is now in process: pycti called reportExpectation over HTTP for EVERY
  // object (success included), which was the second HTTP call per object on the old path.
  if (message.work_id) {
    await reportExpectation(context, user, message.work_id, error ? { error, source: 'chunk intake' } : undefined);
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
  try {
    const { context, user } = await createChunkContext(message, operations);
    // One in-flight operation per object of the chunk, like an HTTP-batched body: ordering
    // inside the chunk is the sequencer's business, not the transport's.
    const results = await Promise.all(operations.map(async (operation) => {
      try {
        const result = await executeChunkOperation(context, operation);
        return result.errors?.length ? String(result.errors[0].message) : undefined;
      } catch (e: any) {
        return String(e.message ?? e);
      }
    }));
    for (let index = 0; index < operations.length; index += 1) {
      await reportChunkOutcome(context, user, message, operations[index], results[index]);
    }
    controls.ack();
    chunksCounter?.add(1, { outcome: 'acked' });
    chunkSeconds?.record((Date.now() - start) / 1000);
  } catch (e: any) {
    // Chunk-level failure (auth, unknown document, platform error): retry once, then dead
    // letter. Per-object failures never reach here: the sequencer parks, defers and reports
    // them internally, and requeuing a chunk for one dead object would replay the rest.
    if (controls.redelivered) {
      logApp.error('[CHUNK-INTAKE] Chunk failed twice, dead lettering', { cause: e, chunk_id: message.chunk_id });
      chunksCounter?.add(1, { outcome: 'dead_letter', reason: 'failed' });
      controls.deadLetter();
    } else {
      logApp.warn('[CHUNK-INTAKE] Chunk failed, requeueing once', { cause: e, chunk_id: message.chunk_id });
      chunksCounter?.add(1, { outcome: 'retried' });
      controls.retry();
    }
  }
};

const chunkIntakeInitializer = async () => {
  registerChunkMetrics();
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
