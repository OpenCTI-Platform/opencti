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
import type { Counter, Gauge, Histogram } from '@opentelemetry/api';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { meterManager } from '../config/tracing';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { chunkIntakeQueue, consumeChunkIntakeQueue, registerChunkIntakeQueue } from '../database/rabbitmq';
import { executeChunkOperation, executeInProcessRead, substituteEchoIds, type ChunkOperation } from '../graphql/chunk-executor';
import { splitEchoIds } from './chunkIntakeEchoes';
import { PreLoopGate } from './chunkIntakePreLoop';
import { resolveProducerIds } from './chunkIntakeProducers';
import { describeIntentLocation, onSequencerQueueTaken, sequencerLoopGauges, sequencerQueueDepth, startSequencerLoop } from '../database/sequencer/sequencer-loop';
import { isSequencerEnabled, SEQUENCER_CONFIG } from '../database/sequencer/sequencer-config';
import { chunkOperationRootField } from './chunkIntakeProducers';
import { stripMemberRefMarks } from '../database/sequencer/sequencer-eligibility';
import {
  deferOperation,
  pendingIntentsAccepting,
  registerPendingIntentSettled,
  pendingRecordInput,
  registerPendingFileStaging,
  registerPendingIntentContext,
  registerPendingOperationExecute,
  type PendingOperationEnvelope,
} from '../database/sequencer/sequencer-pending-intents';
import { DatabaseError, DRAFT_LOCKED_ERROR, EngineShardsError, MISSING_REF_ERROR, SEQUENCER_DEFERRED_ERROR, WORK_NOT_ALIVE_ERROR } from '../config/errors';
import { createIntakeContext } from '../intake/intake-context';
import { consumePushQueues } from '../intake/workerless/push-consumer';
import { createLimiter, PushRefusedError } from '../intake/workerless/push-intake';
import { createReleaseScheduler, type ReleaseScheduler } from '../intake/workerless/release-scheduler';
import { createImportContext, type ImportContext } from '../intake/stix-import/context';
import { type ImportClient, ImportClientError, type ImportLogger } from '../intake/stix-import/types';
import { connectorsForWorker } from '../modules/connector/connector-domain';
import { connectorConfig } from '../modules/connector/connector-rabbitmq';
import { fullEntitiesList } from '../database/middleware-loader';
import { ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { lockResources } from '../lock/master-lock';
import { TYPE_LOCK_ERROR } from '../config/errors';
import {
  consumedPushQueues,
  createOrderedQueuesLeadership,
  createPartitionSlot,
  intakeLockKey,
  parseQueuePartition,
  partitionedPushQueues,
} from '../intake/workerless/push-queues';
import { isLockError } from '../database/sequencer/sequencer-multi-writer';
import { rehydrateFiles, removeStagedFiles, stageFiles } from '../intake/intake-files';
import { intakeEnvelopeOfMessage, type IntakeEnvelope } from '../intake/intake-envelope';
import { reportWorkProgress } from '../domain/work';
import { chunkWorkProgress, type ChunkWorkFields } from './chunkIntakeWork';
import { isTransitoryError } from '../database/engine';
import { wait } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';

const CHUNK_INTAKE_MANAGER_ID = 'CHUNK_INTAKE_MANAGER';
const CHUNK_INTAKE_MANAGER_CONTEXT = 'chunk_intake_manager';

const CHUNK_INTAKE_MANAGER_ENABLED = booleanConf('chunk_intake_manager:enabled', false);
const CHUNK_INTAKE_MANAGER_KEY = conf.get('chunk_intake_manager:lock_key') || 'chunk_intake_manager_lock';
const SCHEDULE_TIME = Number(conf.get('chunk_intake_manager:interval') ?? 10000);
// 192 (was 8): chunks in flight; prefetch x chunk size is the single flow-control valve of the
// path. 128 was the operating point since 2026-09-15; 192 read equal on mix140k (ladder 3,
// 2026-09-25) with the queue cap at 40,000 intents, 256 brought nothing more.
const PREFETCH = Number(conf.get('chunk_intake_manager:prefetch') ?? 192);
const MAX_TRANSIENT_ATTEMPTS = Number(conf.get('chunk_intake_manager:max_transient_attempts') ?? 20);
// Retry-gap option 1: a creation whose hard reference is still missing after its park
// deadline is RETAINED by the sequencer (pending intents) and re-submitted when the
// reference lands, instead of failing into a client retry ladder that this path removed.
const DEFER_MISSING_REFS = booleanConf('chunk_intake_manager:defer_missing_refs', true);
// Worker-less intake (POC, intake/workerless): 'push_queues' consumes the connector push queues in
// place of the workers (transformation, capture and chunks in process); 'chunk_queue' consumes the
// chunks the workers publish
const CHUNK_INTAKE_SOURCE = conf.get('chunk_intake_manager:source') ?? 'chunk_queue';
// Unacked messages per push queue: a buffer of decoded messages for the release scheduler, not the
// regulator (the set point below is); 25 keeps mix140k's throughput of 100 with 20% less platform
// memory, 10 halves it with half-full batches (2026-11-06 tuning runs). Memory is bounded by the bytes.
const PUSH_PREFETCH = Number(conf.get('chunk_intake_manager:push_prefetch') ?? 25);
const PUSH_MAX_IN_FLIGHT_BYTES = Number(conf.get('chunk_intake_manager:push_max_in_flight_bytes') ?? 268435456);
// The ready depth the release scheduler holds, in sequencer batches (R* = factor x max_batch_size):
// at least one batch keeps the batches full, more only adds write latency (KB note
// opencti-workerless-intake-target-design §4.3; the value comes from a 1 / 2 / 4 ladder)
const PUSH_READY_DEPTH_FACTOR = Number(conf.get('chunk_intake_manager:push_ready_depth_factor') ?? 2);
// Ready operations released from one push queue before the next queue's turn: 1 alternates the
// queues operation by operation, more keeps a connector's objects together (KB note D9, to measure)
const PUSH_RELEASE_QUANTUM = Number(conf.get('chunk_intake_manager:push_release_quantum') ?? 1);
// Transformations running at once: their reads reach the engine outside the pre-loop gate (a read
// per open vocabulary value, author or marking not yet cached)
const PUSH_TRANSFORM_CONCURRENCY = Number(conf.get('chunk_intake_manager:push_transform_concurrency') ?? 16);
// task 0040 queue affinity test (multi_writer): connector groups, one per platform (push-queues.ts); empty = off
const PUSH_QUEUE_PARTITION = parseQueuePartition(conf.get('chunk_intake_manager:push_queue_partition'));
// Per-OPERATION transient policy (depth campaign v2, 2026-09-14: a 240-rejection burst of the
// ES search pool cost 34 indicators at prefetch 48, where pycti's ladder retried them on
// HTTP). A transient engine error inside one operation (rejected execution, circuit breaker,
// 429 / 503, connection resets) is retried in place with backoff while HOLDING the chunk's
// prefetch slot (backpressure on the very pool that is saturating); past the cap the
// operation is RETAINED (pending store, sweeper backoff) instead of being lost.
const OP_TRANSIENT_ATTEMPTS = Number(conf.get('chunk_intake_manager:op_transient_attempts') ?? 5);
const OP_TRANSIENT_BACKOFF_MS = Number(conf.get('chunk_intake_manager:op_transient_backoff_ms') ?? 250);
// Pre-loop admission pacing (ref-b dissection, 2026-09-15): at intake start, prefetch x ~7
// operations start in the same instant with nothing pacing them, and their pre-loop lookups
// (domain pre-resolves, observable lookups) plus the cold identity map's first resolves
// overflow the engine's search queue when nothing else throttles the platform (fewer workers
// = less HTTP bookkeeping = a sharper wave: 1,633 rejections at w1 prefetch 128, none at w8).
// This bounds the number of operations between their execution start and the moment the
// sequencer boundary has queued their intent (or the operation settled): the concurrent
// pre-loop engine lookups are capped at any moment, the depth offered to the loop is not.
// Default 32 (permit probe 2026-09-15, w1 prefetch 128): 64 left 405 search rejections and 61
// retries at intake start, 32 and 16 left none; 32 at 300.4 obj/s (= 64), 16 at 293.5.
const PRE_LOOP_CONCURRENCY = Number(conf.get('chunk_intake_manager:pre_loop_concurrency') ?? 32);
// Adaptive limit (2026-09-24, chunkIntakePreLoop.ts): grows while operations are paced and
// the engine is quiet, halves on transient engine errors. min / max bound the walk, the
// value above is where it starts; adaptive=false pins the legacy fixed limit. Growth is
// +35% per tick; after an engine error it resumes once the engine has been quiet for 3 s
// (three ticks: the search queue drains in well under a second once the burst is gone).
const PRE_LOOP_ADAPTIVE = booleanConf('chunk_intake_manager:pre_loop_adaptive', true);
const PRE_LOOP_MIN = Number(conf.get('chunk_intake_manager:pre_loop_concurrency_min') ?? 8);
// max 256 (was 512): at 512 the start-of-intake burst still left 779 to 1,292 search
// rejections and up to 145 transient retries per mix140k run; 256 left 0 retries and 3x fewer
// rejections at equal throughput (ladder of 2026-09-25).
const PRE_LOOP_MAX = Number(conf.get('chunk_intake_manager:pre_loop_concurrency_max') ?? 256);
const PRE_LOOP_TICK_MS = Number(conf.get('chunk_intake_manager:pre_loop_tick_ms') ?? 1000);
const PRE_LOOP_QUIET_MS = Number(conf.get('chunk_intake_manager:pre_loop_quiet_ms') ?? 3000);
const PRE_LOOP_INCREASE_RATIO = Number(conf.get('chunk_intake_manager:pre_loop_increase_ratio') ?? 0.35);
// Single wave per chunk (2026-09-24, chunkIntakeProducers.ts): producers are resolved to
// their standard ids up front and the whole chunk runs at once; false = the legacy
// producers-first wave (A/B knob). Needs the sequencer: without it nothing orders a
// producer before its consumers.
const SINGLE_WAVE = booleanConf('chunk_intake_manager:single_wave', true);
// Stall probe (2026-09-25): every chunk in flight tracks the phase of each operation (gate =
// waiting for a pre-loop permit, preloop = executing before its intent is queued, queued =
// intent handed to the loop, settled); a watchdog logs the chunks without progress for
// stall_log_after_ms, with their unsettled operations and where the loop holds their intents.
// 0 disables the watchdog. Built after apply_concurrency 16 left two chunks unacked for 25 min.
const STALL_LOG_AFTER_MS = Number(conf.get('chunk_intake_manager:stall_log_after_ms') ?? 120000);
const STALL_WATCH_INTERVAL_MS = Number(conf.get('chunk_intake_manager:stall_watch_interval_ms') ?? 60000);
type OperationPhase = 'pending' | 'gate' | 'preloop' | 'queued' | 'settled';
type InFlightChunk = { startedAt: number; lastProgressAt: number; operations: Map<ChunkOperation, { phase: OperationPhase; since: number }> };
const inFlightChunks = new Map<string, InFlightChunk>();
const trackPhase = (chunk: InFlightChunk | undefined, operation: ChunkOperation, phase: OperationPhase) => {
  if (!chunk) return;
  const now = Date.now();
  chunk.operations.set(operation, { phase, since: now });
  chunk.lastProgressAt = now;
};
let stallWatchdog: NodeJS.Timeout | null = null;
const logStalledChunks = () => {
  const now = Date.now();
  inFlightChunks.forEach((chunk, chunkId) => {
    if (now - chunk.lastProgressAt < STALL_LOG_AFTER_MS) return;
    const byPhase: Record<string, number> = {};
    const unsettled: Record<string, any>[] = [];
    chunk.operations.forEach((state, operation) => {
      byPhase[state.phase] = (byPhase[state.phase] ?? 0) + 1;
      if (state.phase !== 'settled' && unsettled.length < 5) {
        unsettled.push({
          object_id: operation.object_id,
          root: chunkOperationRootField(operation),
          phase: state.phase,
          since_s: Math.round((now - state.since) / 1000),
          loop: state.phase === 'queued' && operation.object_id ? describeIntentLocation([operation.object_id]) : undefined,
        });
      }
    });
    logApp.warn('[CHUNK-INTAKE] chunk without progress', {
      chunk_id: chunkId, age_s: Math.round((now - chunk.startedAt) / 1000), idle_s: Math.round((now - chunk.lastProgressAt) / 1000),
      operations: byPhase, unsettled, loop: sequencerLoopGauges(), gate: { limit: preLoopGate.currentLimit(), in_flight: preLoopGate.inFlight(), waiting: preLoopGate.waiting() },
    });
  });
};
const startStallWatchdog = () => {
  if (stallWatchdog || STALL_LOG_AFTER_MS <= 0) return;
  stallWatchdog = setInterval(logStalledChunks, STALL_WATCH_INTERVAL_MS);
  stallWatchdog.unref?.();
};
const stopStallWatchdog = () => {
  if (stallWatchdog) clearInterval(stallWatchdog);
  stallWatchdog = null;
};
let preLoopLimitGauge: Gauge | null = null;
let preLoopAdjustments: Counter | null = null;
let producersCounter: Counter | null = null;
const preLoopGate = new PreLoopGate({
  initial: PRE_LOOP_CONCURRENCY,
  min: PRE_LOOP_MIN,
  max: PRE_LOOP_MAX,
  adaptive: PRE_LOOP_ADAPTIVE,
  increaseRatio: PRE_LOOP_INCREASE_RATIO,
  quietMs: PRE_LOOP_QUIET_MS,
  onLimitChange: (limit, direction) => {
    preLoopLimitGauge?.record(limit);
    preLoopAdjustments?.add(1, { direction });
  },
});
let preLoopTicker: NodeJS.Timeout | null = null;
const startPreLoopTicker = () => {
  if (preLoopTicker || !preLoopGate.enabled() || !PRE_LOOP_ADAPTIVE) return;
  preLoopTicker = setInterval(() => preLoopGate.tick(), PRE_LOOP_TICK_MS);
  preLoopTicker.unref?.();
};
const stopPreLoopTicker = () => {
  if (preLoopTicker) clearInterval(preLoopTicker);
  preLoopTicker = null;
};

// Gate-only fault injection: the first N consumer operations of the process fail once with a
// synthetic transient error (statusCode 429), so the retry path is exercised deterministically.
let faultTransientBudget = Number(conf.get('chunk_intake_manager:fault_transient_ops') ?? 0);

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

// A write the platform refuses before it runs, as the HTTP edge refuses a worker's request: the
// worker's outcome is kept (pycti import_item_with_retries). A deleted work (WORK_NOT_ALIVE):
// skipped, nothing reported, the work is gone. A draft no longer open (DRAFT_LOCKED): skipped,
// each object reported in error. Acked either way: no redelivery can change it.
export class ChunkRefusedError extends Error {
  readonly reason: 'work_not_alive' | 'draft_locked';

  constructor(message: string, reason: 'work_not_alive' | 'draft_locked') {
    super(message);
    this.name = 'ChunkRefusedError';
    this.reason = reason;
  }
}

// Attempts of currently failing chunks only: cleared on ack or dead-letter, so the map
// stays tiny (memory-only: a restart resets the count, the cap still bounds the total).
const transientAttempts = new Map<string, number>();

// The envelope of the push message (writer, applicant, work, draft, event, playbook,
// synchronized, previous standard, retry number: intake-context.ts) and the chunk itself
interface ChunkMessage extends ChunkWorkFields, IntakeEnvelope {
  v?: number;
  chunk_id?: string;
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
  // adaptive pre-loop gate (2026-09-24): the limit as it moves, and its adjustments
  preLoopLimitGauge = meter.createGauge('opencti_chunk_intake_pre_loop_limit', {
    valueType: ValueType.INT,
    description: 'Current pre-loop admission limit (operations between start and intent queued)',
  });
  preLoopAdjustments = meter.createCounter('opencti_chunk_intake_pre_loop_adjustments_total', {
    valueType: ValueType.INT,
    description: 'Pre-loop limit adjustments by direction (up, down)',
  });
  producersCounter = meter.createCounter('opencti_chunk_intake_producers_total', {
    valueType: ValueType.INT,
    description: 'Chunk producers by resolution (standard_id up front, executed_first legacy)',
  });
  preLoopLimitGauge.record(preLoopGate.currentLimit());
  chunkSeconds = meter.createHistogram('opencti_chunk_intake_chunk_seconds', {
    valueType: ValueType.DOUBLE,
    description: 'Wall time from chunk delivery to chunk ack',
  });
};
// endregion

// Builds the execution context a chunk runs under. Deliberately mirrors the HTTP one
// (httpAuthenticatedContext) field for field, minus everything request-shaped: same user
// resolution, same member-mark strip over the whole chunk, same batch loaders.
export const createChunkContext = async (message: ChunkMessage, operations: ChunkOperation[], memberIds?: Iterable<string>) => {
  // The context the worker's request would have had (intake-context.ts): the writer resolved
  // from the envelope (no token ever travels through the queue), the applicant impersonated,
  // work alive and draft open checked. Worker origin (sequencer eligibility) is carried by the
  // retry-number header: presence is what counts, "0" is the legitimate first attempt.
  let built: { context: AuthContext; user: AuthUser };
  try {
    built = await createIntakeContext(intakeEnvelopeOfMessage(message), CHUNK_INTAKE_MANAGER_CONTEXT);
  } catch (e: any) {
    const code = e?.extensions?.code;
    if (code === WORK_NOT_ALIVE_ERROR) {
      throw new ChunkRefusedError(`Chunk work is no longer alive (${message.work_id})`, 'work_not_alive');
    }
    if (code === DRAFT_LOCKED_ERROR) {
      throw new ChunkRefusedError(`Chunk draft is not open (${message.draft_id}): ${e.message}`, 'draft_locked');
    }
    // The writer or the applicant is gone or refused: no redelivery can change that.
    throw new ChunkPoisonError(`Chunk writer cannot be resolved (${message.applicant_id ?? message.user_id}): ${e.message}`, 'unknown_writer');
  }
  const context = built.context as any;
  context.deferMissingRefs = DEFER_MISSING_REFS;
  // ||M|| marks are transport-only: strip them for the WHOLE chunk before any coercion or
  // resolution, exactly as the HTTP edge does for a batched body. The union rides the context
  // to the sequencer boundary, where it classifies a missing ref as an in-chunk member.
  const memberRefs = new Set<string>();
  operations.forEach((operation) => {
    if (operation?.variables) stripMemberRefMarks(operation.variables, memberRefs);
  });
  // producers resolved by standard id (single wave): in-chunk members too, so a consumer
  // planned before its producer's intent is seen waits for it (member_wait) instead of
  // parking as an external reference
  if (memberIds) Array.from(memberIds).forEach((id) => memberRefs.add(id));
  if (memberRefs.size > 0) {
    context.memberRefIds = memberRefs;
  }
  return { context: context as AuthContext, user: built.user };
};

// Outcome of one operation: ok, failed with an error, or RETAINED (its hard reference is
// still missing: the creation is stored and re-submitted when the reference lands, so it is
// neither an error nor a completion yet). Two retention paths: the sequencer loop retains
// the INTENT (SEQUENCER_DEFERRED), the manager retains the OPERATION when the reference
// check failed OUTSIDE the loop (MISSING_REFERENCE_ERROR reaching the executor: a domain
// pre-resolve such as addIndicator's, which the loop hooks never see).
export interface OperationOutcome {
  error?: string;
  deferred?: boolean;
  // The id the platform gave a producer whose id is substituted
  id?: string;
}

// A GraphQL error out of execute wraps the resolver's error as originalError; engine errors
// carry their cause (shard failures included) under extensions.data. isTransitoryError walks
// both shapes (status codes, connection codes, rejected execution / circuit breaker text).
// isTransitoryError walks fixed paths only: an ES shard rejection surfaces as
// DatabaseError('Find direct ids fail', { cause: EngineShardsError({ shards }) }) and its
// shards.failures[].reason.type = es_rejected_execution_exception sits below every path it
// reads (ref campaign w2 pf96: 103 indicators lost, 427 rejections, zero retries). Fallback:
// the serialized error chain, bounded, matched on the engine's transient signatures.
const TRANSIENT_SIGNATURES = /es_rejected_execution|circuit_breaking|too_many_requests|service_unavailable|rejected execution/i;
const errorChainText = (err: any): string => {
  const seen = new WeakSet<object>();
  const safe = (value: any, depth: number): any => {
    if (value === null || typeof value !== 'object' || depth > 12) return typeof value === 'string' ? value.slice(0, 500) : value;
    if (seen.has(value)) return undefined;
    seen.add(value);
    if (Array.isArray(value)) return value.slice(0, 20).map((v) => safe(v, depth + 1));
    const out: Record<string, any> = {};
    Object.getOwnPropertyNames(value).forEach((key) => {
      if (key === 'stack') return;
      out[key] = safe(value[key], depth + 1);
    });
    return out;
  };
  try {
    return JSON.stringify(safe({ err, original: err?.originalError, data: err?.extensions?.data, originalData: err?.originalError?.extensions?.data }, 0)).slice(0, 32768);
  } catch {
    return String(err?.message ?? err);
  }
};
const isTransientOperationError = (err: any): boolean => isTransitoryError(err)
  || isTransitoryError(err?.originalError)
  || isTransitoryError(err?.originalError?.extensions?.data?.cause)
  || isTransitoryError(err?.extensions?.data?.cause)
  || TRANSIENT_SIGNATURES.test(errorChainText(err));

const unresolvedIdsOf = (err: any): string[] => {
  const ids = err?.extensions?.data?.unresolvedIds ?? err?.originalError?.extensions?.data?.unresolvedIds ?? err?.data?.unresolvedIds;
  return Array.isArray(ids) ? ids.map(String) : [];
};

const envelopeOf = (message: ChunkMessage): PendingOperationEnvelope => intakeEnvelopeOfMessage(message);

const reportChunkOutcome = async (
  context: AuthContext,
  user: AuthUser,
  message: ChunkMessage,
  operation: ChunkOperation,
  outcome: OperationOutcome,
) => {
  if (outcome.deferred) {
    // retained: counted with its chunk, an expiry adds an error (registerPendingIntentSettled)
    operationsCounter?.add(1, { outcome: 'deferred' });
    return;
  }
  if (outcome.error) {
    logApp.error('[CHUNK-INTAKE] Operation failed', { chunk_id: message.chunk_id, object_id: operation.object_id, error: outcome.error });
  }
  operationsCounter?.add(1, { outcome: outcome.error ? 'error' : 'ok' });
};

// Work accounting (ADR 0007): the chunk's objects in ONE report, after the ack. After, not
// before: a report failure must never requeue the chunk, whose replay would count it twice.
const reportChunkWork = async (
  context: AuthContext,
  user: AuthUser,
  message: ChunkMessage,
  operations: ChunkOperation[],
  results: { error?: string; deferred?: boolean }[],
) => {
  if (!message.work_id) return;
  const progress = chunkWorkProgress(message, operations, results);
  if (progress.count === 0 && progress.errors.length === 0) return;
  try {
    await reportWorkProgress(context, user, message.work_id, progress);
  } catch (err) {
    logApp.error('[CHUNK-INTAKE] Work report failed', { cause: err, chunk_id: message.chunk_id, work_id: message.work_id });
  }
};

// A dead-lettered chunk still meets its work: its objects are counted in error, so the work
// can complete instead of waiting for objects that will never come.
const reportDeadLetteredChunkWork = async (message: ChunkMessage, operations: ChunkOperation[], reason: string) => {
  if (!message.work_id) return;
  const results = operations.map(() => ({ error: `chunk dead-lettered (${reason})` }));
  await reportChunkWork(executionContext(CHUNK_INTAKE_MANAGER_CONTEXT), SYSTEM_USER, message, operations, results);
};

// pycti reports each object of a draft no longer open in error, source "Draft in read only"
const reportRefusedChunkWork = async (message: ChunkMessage, operations: ChunkOperation[], error: string) => {
  if (!message.work_id) return;
  const results = operations.map(() => ({ error }));
  await reportChunkWork(executionContext(CHUNK_INTAKE_MANAGER_CONTEXT), SYSTEM_USER, message, operations, results);
};

// One operation of the intake run to its end, for a chunk (processChunk) or a push message
// (worker-less intake): a pre-loop permit per attempt, released once its intent is queued (or it
// settled without reaching the loop); transient engine errors retried in place, then the operation
// retained; a reference missing outside the loop retains the operation; a producer whose id is
// substituted (producerFirst) returns the id the platform gave it.
export interface IntakeOperationRun {
  // The chunk or the message, for the logs
  key?: string;
  context: AuthContext;
  user: AuthUser;
  envelope: PendingOperationEnvelope;
  operation: ChunkOperation;
  producerFirst: boolean;
  // Its intent is queued in the sequencer, or it settled without reaching it (called again after)
  onQueued: () => void;
  onPhase?: (phase: OperationPhase) => void;
}

// Transient engine error on a consumer: retry in place with backoff, then retain.
const transientOutcome = async (run: IntakeOperationRun, err: any, attempt: number): Promise<OperationOutcome | null> => {
  const { operation, key, user } = run;
  if (!isTransientOperationError(err)) return null;
  preLoopGate.onEngineError(); // the adaptive gate halves on engine trouble, whatever becomes of the operation
  if (run.producerFirst) return null;
  if (attempt < OP_TRANSIENT_ATTEMPTS) {
    const backoffMs = Math.min(OP_TRANSIENT_BACKOFF_MS * 2 ** attempt, 4000);
    logApp.warn('[CHUNK-INTAKE] Operation retried (transient engine error)', {
      key, object_id: operation.object_id, attempt: attempt + 1, backoffMs, cause: String(err?.message ?? err),
    });
    operationsCounter?.add(1, { outcome: 'transient_retry' });
    await wait(backoffMs);
    return { deferred: false }; // sentinel: retry
  }
  if (DEFER_MISSING_REFS && pendingIntentsAccepting()) {
    const retained = await deferOperation({ operation, envelope: run.envelope, user, missing: [] });
    if (retained) {
      logApp.warn('[CHUNK-INTAKE] Operation retained after transient retries (sweeper will re-execute)', {
        key, object_id: operation.object_id, attempts: attempt, cause: String(err?.message ?? err),
      });
      return { deferred: true };
    }
  }
  return null;
};
// pycti parity (opencti_stix2.py import_item): an operation refused because its entities are
// locked waits 1 to 3 s and runs again, without limit; the worker-less intake failed it (task 0040:
// invisible on one platform, 2,968 operations lost at two)
const lockRetryOutcome = async (err: any): Promise<OperationOutcome | null> => {
  if (!isLockError(err)) return null;
  operationsCounter?.add(1, { outcome: 'lock_retry' });
  await wait(1000 + Math.round(Math.random() * 2000));
  return { deferred: false }; // sentinel: retry
};
const runOperationOnce = async (run: IntakeOperationRun, attempt: number): Promise<OperationOutcome> => {
  const { operation, key, user } = run;
  // one pre-loop permit per attempt, released by the boundary hook (intent queued) or,
  // for operations that never reach the loop, when the operation settles
  run.onPhase?.('gate');
  const waited = await preLoopGate.acquire();
  if (waited) operationsCounter?.add(1, { outcome: 'paced' });
  run.onPhase?.('preloop');
  let released = false;
  const releaseOnce = () => {
    if (released) return;
    released = true;
    preLoopGate.release();
  };
  const opContext: AuthContext = {
    ...run.context,
    onIntentQueued: () => {
      releaseOnce();
      run.onQueued();
      run.onPhase?.('queued');
    },
  };
  try {
    if (faultTransientBudget > 0 && attempt === 0 && !operation.echo_id) {
      faultTransientBudget -= 1;
      // the REAL shape of an ES shard rejection on the chunk path (ref campaign w2 pf96):
      // DatabaseError('Find direct ids fail') wrapping EngineShardsError({ shards })
      throw DatabaseError('Find direct ids fail (synthetic transient fault, chunk_intake_manager.fault_transient_ops)', {
        cause: EngineShardsError({ shards: { total: 1, successful: 0, failed: 1, failures: [{ reason: { type: 'es_rejected_execution_exception', reason: 'rejected execution (synthetic)' } }] } }),
      });
    }
    const result = await executeChunkOperation(opContext, operation);
    if (result.errors?.length) {
      const first: any = result.errors[0];
      const code = first?.extensions?.code;
      if (code === SEQUENCER_DEFERRED_ERROR) {
        return { deferred: true };
      }
      const locked = await lockRetryOutcome(first);
      if (locked) return locked;
      const transient = await transientOutcome(run, first, attempt);
      if (transient) return transient;
      // A consumer refused for a missing reference before it reached the loop: retain
      // the operation (a producer executed first keeps the error path: its consumers
      // already ran).
      if (code === MISSING_REF_ERROR && !run.producerFirst && DEFER_MISSING_REFS && pendingIntentsAccepting()) {
        const { resolvable: missing, echoes } = splitEchoIds(unresolvedIdsOf(first));
        if (echoes.length > 0) {
          // B12: an unresolved echo id has no producer that can still land (it leaked
          // from another capture window, A9, or its producer failed): retaining the
          // operation would park it until expiry. Fail it, visibly.
          logApp.error('[CHUNK-INTAKE] Operation refused: unresolved echo id (no producer in its chunk)', {
            key, object_id: operation.object_id, echoes, missing,
          });
          operationsCounter?.add(1, { outcome: 'echo_unresolved' });
          return { error: `unresolved echo id: ${echoes.join(', ')}` };
        }
        const retained = await deferOperation({ operation, envelope: run.envelope, user, missing });
        if (retained) {
          logApp.info('[CHUNK-INTAKE] Operation retained (missing reference outside the loop)', {
            key, object_id: operation.object_id, missing,
          });
          return { deferred: true };
        }
      }
      return { error: String(first.message) };
    }
    if (operation.echo_id && run.producerFirst) {
      const root: any = result.data ? Object.values(result.data)[0] : undefined;
      if (root?.id) return { id: String(root.id) };
    }
    return {};
  } catch (e: any) {
    const locked = await lockRetryOutcome(e);
    if (locked) return locked;
    const transient = await transientOutcome(run, e, attempt);
    if (transient) return transient;
    return { error: String(e.message ?? e) };
  } finally {
    releaseOnce();
  }
};
// deferred === false is the retry sentinel of transientOutcome: loop until a real outcome
// Settled without reaching the loop (or after it) counts as queued for what waits on it, once
// the last attempt is over: a transient retry is not an end.
export const runIntakeOperation = async (run: IntakeOperationRun): Promise<OperationOutcome> => {
  try {
    for (let attempt = 0; ; attempt += 1) {
      const outcome = await runOperationOnce(run, attempt);
      if (outcome.deferred !== false) return outcome;
    }
  } finally {
    run.onQueued();
    run.onPhase?.('settled');
  }
};

export const processChunkMessage = async (payload: string, controls: ChunkControls) => {
  let message: ChunkMessage;
  try {
    message = JSON.parse(payload);
  } catch (e: any) {
    logApp.error('[CHUNK-INTAKE] Unparsable chunk message, dead lettering', { cause: e });
    chunksCounter?.add(1, { outcome: 'dead_letter', reason: 'unparsable' });
    controls.deadLetter();
    return;
  }
  await processChunk(message, controls, payload);
};

// One chunk, from the chunk queue (parsed) or from the worker-less intake (in process: its
// operations may carry files, which no queue message could)
export const processChunk = async (message: ChunkMessage, controls: ChunkControls, payload?: string) => {
  const start = Date.now();
  const operations = Array.isArray(message.operations) ? message.operations : [];
  if (operations.length === 0) {
    logApp.error('[CHUNK-INTAKE] Chunk without operations, dead lettering', { chunk_id: message.chunk_id });
    chunksCounter?.add(1, { outcome: 'dead_letter', reason: 'empty' });
    controls.deadLetter();
    return;
  }
  // A chunk without an id (hand-published) is keyed by its payload head: same policy.
  const attemptKey = message.chunk_id ?? (payload ?? JSON.stringify(operations)).slice(0, 128);
  const tracked: InFlightChunk = { startedAt: start, lastProgressAt: start, operations: new Map() };
  operations.forEach((operation) => tracked.operations.set(operation, { phase: 'pending', since: start }));
  inFlightChunks.set(attemptKey, tracked);
  try {
    // Producers (pycti's pre-created sub-objects, answered with echo ids on the capture
    // transport) are resolved to their STANDARD ids before anything runs, so the chunk is
    // one wave and the sequencer orders producers before consumers (chunkIntakeProducers.ts).
    // Producers the platform cannot resolve up front, or every producer when the single
    // wave is off, keep the legacy path: executed first, real ids substituted.
    const singleWave = SINGLE_WAVE && isSequencerEnabled();
    const upFront = singleWave
      ? resolveProducerIds(operations)
      : { resolved: new Map<string, string>(), unresolved: operations.filter((operation) => !!operation.echo_id) };
    const { resolved } = upFront;
    const producerFirst = new Set<ChunkOperation>(upFront.unresolved);
    if (resolved.size > 0) {
      operations.forEach((operation) => {
        if (!operation.echo_id && operation.variables) substituteEchoIds(operation.variables, resolved);
      });
      producersCounter?.add(resolved.size, { resolution: 'standard_id' });
    }
    if (producerFirst.size > 0) producersCounter?.add(producerFirst.size, { resolution: 'executed_first' });
    const { context, user } = await createChunkContext(message, operations, resolved.values());
    // Single wave ordering (probe 2026-09-24): a producer reaches the queue only after its
    // pre-loop lookups (addLabel reads before it creates) while its consumer reaches it at
    // once; when a batch boundary falls between the two, the consumer applies with the
    // producer still queued and its soft ref is stripped, then reconciled one intent per
    // cycle (86 course-of-action label refs per MITRE run). Consumers therefore start once
    // every producer of the chunk is QUEUED (or settled without reaching the loop): FIFO then
    // puts the producer in the same batch (edge) or an earlier one (committed), never behind.
    // No commit is awaited: the wait is the producers' pre-loop, milliseconds.
    const queuedGates = new Map<ChunkOperation, () => void>();
    const queuedOrSettled = (operation: ChunkOperation) => new Promise<void>((resolve) => {
      queuedGates.set(operation, resolve);
    });
    const markQueued = (operation: ChunkOperation) => {
      const release = queuedGates.get(operation);
      if (release) {
        queuedGates.delete(operation);
        release();
      }
    };
    const runOperation = (operation: ChunkOperation) => runIntakeOperation({
      key: message.chunk_id,
      context,
      user,
      envelope: envelopeOf(message),
      operation,
      producerFirst: producerFirst.has(operation),
      onQueued: () => markQueued(operation),
      onPhase: (phase) => trackPhase(tracked, operation, phase),
    }).then((outcome) => {
      if (operation.echo_id && outcome.id) resolved.set(operation.echo_id, outcome.id);
      return outcome;
    });
    // Wave 1 = the producers that must execute first (legacy path, or unresolvable up
    // front); wave 2 = everything else at once. With every producer resolved by standard
    // id, wave 1 is empty and the chunk is a single wave.
    const first = operations.filter((operation) => producerFirst.has(operation));
    const rest = operations.filter((operation) => !producerFirst.has(operation));
    const firstErrors = await Promise.all(first.map(runOperation));
    if (first.length > 0 && resolved.size > 0) {
      rest.forEach((operation) => {
        if (!operation.echo_id && operation.variables) substituteEchoIds(operation.variables, resolved);
      });
    }
    // producers resolved by standard id start first and only need to be QUEUED before the
    // consumers start (see queuedGates above); everything then completes together
    const producers = rest.filter((operation) => !!operation.echo_id);
    const consumers = rest.filter((operation) => !operation.echo_id);
    const producerGates = producers.map((operation) => queuedOrSettled(operation));
    const producerRuns = producers.map((operation) => runOperation(operation));
    await Promise.all(producerGates);
    const consumerRuns = consumers.map((operation) => runOperation(operation));
    const restErrors = await Promise.all([...producerRuns, ...consumerRuns]);
    const ordered = [...first, ...producers, ...consumers];
    const results = [...firstErrors, ...restErrors];
    for (let index = 0; index < ordered.length; index += 1) {
      await reportChunkOutcome(context, user, message, ordered[index], results[index]);
    }
    controls.ack();
    await reportChunkWork(context, user, message, ordered, results);
    inFlightChunks.delete(attemptKey);
    transientAttempts.delete(attemptKey);
    chunksCounter?.add(1, { outcome: 'acked' });
    objectsCounter?.add(new Set(operations.map((operation) => operation.object_id).filter((id) => !!id)).size);
    chunkSeconds?.record((Date.now() - start) / 1000);
  } catch (e: any) {
    inFlightChunks.delete(attemptKey);
    if (e instanceof ChunkRefusedError) {
      logApp.warn('[CHUNK-INTAKE] Chunk refused, acked without execution', { chunk_id: message.chunk_id, reason: e.reason, cause: e.message });
      chunksCounter?.add(1, { outcome: 'refused', reason: e.reason });
      transientAttempts.delete(attemptKey);
      controls.ack();
      if (e.reason === 'draft_locked') {
        await reportRefusedChunkWork(message, operations, e.message);
      }
      return;
    }
    if (e instanceof ChunkPoisonError) {
      logApp.error('[CHUNK-INTAKE] Poison chunk, dead lettering', { cause: e, chunk_id: message.chunk_id, reason: e.reason });
      chunksCounter?.add(1, { outcome: 'dead_letter', reason: e.reason });
      transientAttempts.delete(attemptKey);
      controls.deadLetter();
      await reportDeadLetteredChunkWork(message, operations, e.reason);
      return;
    }
    const attempts = (transientAttempts.get(attemptKey) ?? 0) + 1;
    if (attempts > MAX_TRANSIENT_ATTEMPTS) {
      logApp.error('[CHUNK-INTAKE] Chunk failed past the transient retry cap, dead lettering', { cause: e, chunk_id: message.chunk_id, attempts });
      chunksCounter?.add(1, { outcome: 'dead_letter', reason: 'transient_cap' });
      transientAttempts.delete(attemptKey);
      controls.deadLetter();
      await reportDeadLetteredChunkWork(message, operations, 'transient_cap');
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

// region worker-less intake (POC): the push queues consumed in place of the workers
// The reads of the transformation, in process under the message's context (built on the first read)
const readsClientFor = (envelope: IntakeEnvelope): ImportClient => {
  let built: ReturnType<typeof createIntakeContext> | null = null;
  return {
    query: async (document: string, variables: Record<string, unknown> = {}) => {
      built = built ?? createIntakeContext(envelope, CHUNK_INTAKE_MANAGER_CONTEXT);
      const { context } = await built;
      const result = await executeInProcessRead(context, document, variables as Record<string, any>);
      if (result.errors?.length) {
        const first: any = result.errors[0];
        throw new ImportClientError(first?.extensions?.code ?? 'INTERNAL_SERVER_ERROR', String(first?.message));
      }
      return result.data;
    },
  };
};

let pushMessagesCounter: Counter | null = null;
// The scheduler of the running consumer, read by the gauge registered once (a re-election builds a new one)
let workerlessScheduler: ReleaseScheduler | null = null;
let workerlessGaugeRegistered = false;
const consumeWorkerlessIntake = async (): Promise<ChunkConsumer> => {
  pushMessagesCounter = meterManager.meterProvider.getMeter('opencti-chunk-intake').createCounter('opencti_workerless_intake_messages_total', {
    valueType: ValueType.INT,
    description: 'Push messages of the worker-less intake, by outcome (written, undecodable, transformation_failed, chunk_dead_lettered, work_not_alive, draft_locked)',
  });
  // pycti keeps its caches for the life of the worker, one per draft
  const contexts = new Map<string, ImportContext>();
  const logger: ImportLogger = { error: () => {}, warn: () => {} };
  const contextFor = (draftId: string) => {
    let context = contexts.get(draftId);
    if (!context) {
      context = createImportContext({ query: async () => {
        throw new Error('reads go through the message client');
      } }, logger, { draftId });
      contexts.set(draftId, context);
    }
    return context;
  };
  // multi_writer: the queues of the stream synchronizations are consumed by the platform holding the
  // intake's historical lock only (push-queues.ts)
  const leadership = SEQUENCER_CONFIG.multiWriter
    ? createOrderedQueuesLeadership(() => lockResources([CHUNK_INTAKE_MANAGER_KEY], { retryCount: 0 })
        .catch((e: any) => (e?.name === TYPE_LOCK_ERROR ? null : Promise.reject(e))))
    : null;
  const partition = SEQUENCER_CONFIG.multiWriter && PUSH_QUEUE_PARTITION.length > 0
    ? createPartitionSlot(PUSH_QUEUE_PARTITION.length, (slot) => lockResources([`${CHUNK_INTAKE_MANAGER_KEY}_partition_${slot}`], { retryCount: 0 })
        .catch((e: any) => (e?.name === TYPE_LOCK_ERROR ? null : Promise.reject(e))))
    : null;
  const listQueues = async () => {
    const context = executionContext(CHUNK_INTAKE_MANAGER_CONTEXT);
    const pushConnectors = (await connectorsForWorker(context, SYSTEM_USER))
      .map((connector: any) => ({ name: connector.name, queue: connector.config?.push }))
      .filter((connector: { queue: unknown }): connector is { name: string; queue: string } => typeof connector.queue === 'string');
    // One consumer per queue, as the worker: connectorsForWorker lists some queues twice (background tasks)
    const queues = partition
      ? partitionedPushQueues(pushConnectors, PUSH_QUEUE_PARTITION, await partition.refresh())
      : [...new Set(pushConnectors.map(({ queue }) => queue))];
    if (!leadership || await leadership.refresh()) return queues;
    const syncs = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_SYNC]);
    const ordered = new Set([connectorConfig('sync').push, ...syncs.map((sync) => connectorConfig(sync.internal_id).push)]);
    return consumedPushQueues(queues, ordered, false);
  };
  // The operations are released against the sequencer's queue: R* = factor x max batch
  const setPoint = Math.max(1, Math.round(PUSH_READY_DEPTH_FACTOR * SEQUENCER_CONFIG.maxBatchSize));
  const scheduler = createReleaseScheduler({ queueDepth: sequencerQueueDepth, setPoint: () => setPoint, quantum: PUSH_RELEASE_QUANTUM });
  workerlessScheduler = scheduler;
  const unsubscribe = onSequencerQueueTaken(scheduler.notify);
  if (!workerlessGaugeRegistered) {
    workerlessGaugeRegistered = true;
    meterManager.meterProvider.getMeter('opencti-chunk-intake').createObservableGauge('opencti_workerless_intake_operations', {
      valueType: ValueType.INT,
      description: 'Operations of the worker-less intake by state (waiting, ready, pre_loop) and the ready depth with its set point',
    }).addCallback((result) => {
      const stats: Record<string, number> = workerlessScheduler?.stats() ?? {};
      Object.entries(stats).forEach(([state, value]) => result.observe(value, { state }));
    });
  }
  // The write context of a message: the chunk context rules (intake-context.ts), its refusals
  const writeContext = async (envelope: IntakeEnvelope, operations: ChunkOperation[], memberIds: Iterable<string>) => {
    try {
      return await createChunkContext(envelope, operations, memberIds);
    } catch (e: any) {
      if (e instanceof ChunkRefusedError) {
        if (e.reason === 'draft_locked') await reportRefusedChunkWork(envelope, operations, e.message);
        throw new PushRefusedError(e.message, e.reason);
      }
      if (e instanceof ChunkPoisonError) throw new PushRefusedError(e.message, 'unknown_writer');
      throw e;
    }
  };
  const report = async (key: string, context: AuthContext, user: AuthUser, envelope: IntakeEnvelope, operations: ChunkOperation[], outcomes: OperationOutcome[]) => {
    const message: ChunkMessage = { ...envelope, chunk_id: key };
    for (let index = 0; index < operations.length; index += 1) {
      await reportChunkOutcome(context, user, message, operations[index], outcomes[index]);
    }
    await reportChunkWork(context, user, message, operations, outcomes);
    objectsCounter?.add(new Set(operations.map((operation) => operation.object_id).filter((id) => !!id)).size);
  };
  logApp.info('[OPENCTI-MODULE] Worker-less intake: operations released against the sequencer queue', { set_point: setPoint, factor: PUSH_READY_DEPTH_FACTOR });
  const consumer = await consumePushQueues(
    listQueues,
    {
      scheduler,
      transformations: createLimiter(PUSH_TRANSFORM_CONCURRENCY),
      isTransient: isTransientOperationError,
      readsClient: readsClientFor,
      contextFor,
      writeContext,
      runOperation: runIntakeOperation,
      report,
    },
    { prefetch: PUSH_PREFETCH, maxInFlightBytes: PUSH_MAX_IN_FLIGHT_BYTES },
    (outcome) => pushMessagesCounter?.add(1, { outcome: outcome.reason }),
  );
  return {
    ...consumer,
    alive: () => consumer.alive() && !leadership?.lost() && !partition?.lost(),
    close: async () => {
      unsubscribe();
      await consumer.close();
      await leadership?.release();
      await partition?.release();
    },
  };
};
// endregion

const chunkIntakeInitializer = async () => {
  registerChunkMetrics();
  startPreLoopTicker();
  startStallWatchdog();
  // Terminal outcome of a retained creation: its chunk already counted it (ADR 0007), so a
  // landing reports nothing and an expiry or a failure only adds the error to the work.
  registerPendingIntentSettled(async (record, error) => {
    if (!record.work_id || !error) return;
    const settleContext = executionContext(CHUNK_INTAKE_MANAGER_CONTEXT);
    await reportWorkProgress(settleContext, SYSTEM_USER, record.work_id, { count: 0, errors: [{ error, source: 'chunk intake (retained creation)' }] });
  });
  // The files of a retained record: staged in the object storage, read back on re-execution,
  // deleted once it is settled (intake-files.ts)
  registerPendingFileStaging({ stage: (value, prefix) => stageFiles(value, prefix), rehydrate: (value) => rehydrateFiles(value), remove: (keys) => removeStagedFiles(keys) });
  // Re-submission of a retained INTENT: the context of its intake envelope (a record written
  // before the envelope existed keeps the legacy context of the middleware)
  registerPendingIntentContext(async (record) => {
    if (!record.envelope_json) return null;
    return createIntakeContext(JSON.parse(record.envelope_json), CHUNK_INTAKE_MANAGER_CONTEXT);
  });
  // Re-execution of a retained OPERATION: a fresh chunk context (the writer resolved from
  // the envelope, so no SYSTEM_USER divergence after a restart), the same in-process
  // executor. Outcomes: landed, handed to the loop (retained as an intent), still missing
  // (re-deferred here, attempts + 1), or a terminal failure (thrown, visible).
  registerPendingOperationExecute(async (record) => {
    const operation: ChunkOperation = await pendingRecordInput(record);
    const envelope: PendingOperationEnvelope = record.opts_json ? JSON.parse(record.opts_json) : {};
    const { context, user } = await createChunkContext({ ...envelope, chunk_id: `retained-${record.id}` }, [operation]);
    const result = await executeChunkOperation(context, operation);
    if (result.errors?.length) {
      const first: any = result.errors[0];
      const code = first?.extensions?.code;
      if (code === SEQUENCER_DEFERRED_ERROR) return 'handed';
      if (code === MISSING_REF_ERROR) {
        const { resolvable: missing, echoes } = splitEchoIds(unresolvedIdsOf(first));
        // B12: a retained record still waiting on an echo id will never land: terminal, visible
        if (echoes.length > 0) throw new Error(`unresolved echo id: ${echoes.join(', ')}`);
        await deferOperation({ operation, envelope, user, missing });
        return 'redeferred';
      }
      throw new Error(String(first.message));
    }
    return 'applied';
  });
  // The sequencer's stores (pending intents, pending refs) must exist before the first chunk:
  // the loop starts lazily on its first intent and initialises them in the background, and a
  // retention written in between auto-created a mis-mapped index that killed the loop
  // (2026-09-24). Consume only once the loop is ready.
  if (isSequencerEnabled()) {
    await startSequencerLoop();
  }
  let consumer: ChunkConsumer;
  if (CHUNK_INTAKE_SOURCE === 'push_queues') {
    consumer = await consumeWorkerlessIntake();
  } else {
    await registerChunkIntakeQueue();
    consumer = await consumeChunkIntakeQueue(PREFETCH, (payload: string, controls: ChunkControls) => {
      processChunkMessage(payload, controls).catch((e) => {
        logApp.error('[CHUNK-INTAKE] Unexpected chunk handling error', { cause: e });
      });
    });
  }
  logApp.info('[OPENCTI-MODULE] Chunk intake manager consuming', {
    source: CHUNK_INTAKE_SOURCE,
    queue: consumer.queue,
    prefetch: PREFETCH,
    pre_loop_concurrency: PRE_LOOP_CONCURRENCY,
    pre_loop_adaptive: PRE_LOOP_ADAPTIVE,
    pre_loop_bounds: [PRE_LOOP_MIN, PRE_LOOP_MAX],
    single_wave: SINGLE_WAVE,
  });
  return {
    consumer,
    shutdown: async () => {
      stopPreLoopTicker();
      stopStallWatchdog();
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
  // Worker-less intake: the push queues of the connectors registered since the last tick
  await cronInput?.consumer?.refresh?.();
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
    // multi_writer: one intake per platform, each under its own lock (push-queues.ts)
    lockKey: intakeLockKey(CHUNK_INTAKE_MANAGER_KEY, SEQUENCER_CONFIG.multiWriter, SEQUENCER_CONFIG.nodeId),
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
