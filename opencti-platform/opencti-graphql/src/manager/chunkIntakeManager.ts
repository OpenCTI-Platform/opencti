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
import { executionContext, isUserInPlatformOrganization, SYSTEM_USER } from '../utils/access';
import { chunkIntakeQueue, consumeChunkIntakeQueue, registerChunkIntakeQueue } from '../database/rabbitmq';
import { executeChunkOperation, substituteEchoIds, type ChunkOperation } from '../graphql/chunk-executor';
import { splitEchoIds } from './chunkIntakeEchoes';
import { PreLoopGate } from './chunkIntakePreLoop';
import { resolveProducerIds } from './chunkIntakeProducers';
import { isSequencerEnabled } from '../database/sequencer/sequencer-config';
import { describeIntentLocation, sequencerLoopGauges, startSequencerLoop } from '../database/sequencer/sequencer-loop';
import { chunkOperationRootField } from './chunkIntakeProducers';
import { stripMemberRefMarks } from '../database/sequencer/sequencer-eligibility';
import {
  deferOperation,
  pendingIntentsAccepting,
  registerPendingIntentSettled,
  registerPendingOperationExecute,
  type PendingOperationEnvelope,
} from '../database/sequencer/sequencer-pending-intents';
import { DatabaseError, EngineShardsError, MISSING_REF_ERROR, SEQUENCER_DEFERRED_ERROR } from '../config/errors';
import { authenticateUserByUserId, userWithOrigin } from '../domain/user';
import { computeLoaders } from '../http/httpAuthenticatedContext';
import { reportExpectation } from '../domain/work';
import { getEntityFromCache } from '../database/cache';
import { isTransitoryError } from '../database/engine';
import { wait } from '../database/utils';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreSettings } from '../types/settings';

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
  // producers resolved by standard id (single wave): in-chunk members too, so a consumer
  // planned before its producer's intent is seen waits for it (member_wait) instead of
  // parking as an external reference
  if (memberIds) Array.from(memberIds).forEach((id) => memberRefs.add(id));
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

// Outcome of one operation: ok, failed with an error, or RETAINED (its hard reference is
// still missing: the creation is stored and re-submitted when the reference lands, so it is
// neither an error nor a completion yet). Two retention paths: the sequencer loop retains
// the INTENT (SEQUENCER_DEFERRED), the manager retains the OPERATION when the reference
// check failed OUTSIDE the loop (MISSING_REFERENCE_ERROR reaching the executor: a domain
// pre-resolve such as addIndicator's, which the loop hooks never see).
interface OperationOutcome {
  error?: string;
  deferred?: boolean;
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

const envelopeOf = (message: ChunkMessage): PendingOperationEnvelope => ({
  user_id: message.user_id,
  applicant_id: message.applicant_id,
  work_id: message.work_id,
  draft_id: message.draft_id,
  retry_number: message.retry_number,
});

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
    // Transient engine error on a consumer: retry in place with backoff, then retain.
    const transientOutcome = async (operation: ChunkOperation, err: any, attempt: number): Promise<OperationOutcome | null> => {
      if (!isTransientOperationError(err)) return null;
      preLoopGate.onEngineError(); // the adaptive gate halves on engine trouble, whatever becomes of the operation
      if (producerFirst.has(operation)) return null;
      if (attempt < OP_TRANSIENT_ATTEMPTS) {
        const backoffMs = Math.min(OP_TRANSIENT_BACKOFF_MS * 2 ** attempt, 4000);
        logApp.warn('[CHUNK-INTAKE] Operation retried (transient engine error)', {
          chunk_id: message.chunk_id, object_id: operation.object_id, attempt: attempt + 1, backoffMs, cause: String(err?.message ?? err),
        });
        operationsCounter?.add(1, { outcome: 'transient_retry' });
        await wait(backoffMs);
        return { deferred: false }; // sentinel: retry
      }
      if (DEFER_MISSING_REFS && pendingIntentsAccepting()) {
        const retained = await deferOperation({ operation, envelope: envelopeOf(message), user, missing: [] });
        if (retained) {
          logApp.warn('[CHUNK-INTAKE] Operation retained after transient retries (sweeper will re-execute)', {
            chunk_id: message.chunk_id, object_id: operation.object_id, attempts: attempt, cause: String(err?.message ?? err),
          });
          return { deferred: true };
        }
      }
      return null;
    };
    const runOperationOnce = async (operation: ChunkOperation, attempt: number): Promise<OperationOutcome> => {
      // one pre-loop permit per attempt, released by the boundary hook (intent queued) or,
      // for operations that never reach the loop, when the operation settles
      trackPhase(tracked, operation, 'gate');
      const waited = await preLoopGate.acquire();
      if (waited) operationsCounter?.add(1, { outcome: 'paced' });
      trackPhase(tracked, operation, 'preloop');
      let released = false;
      const releaseOnce = () => {
        if (released) return;
        released = true;
        preLoopGate.release();
      };
      const opContext: AuthContext = {
        ...context,
        onIntentQueued: () => {
          releaseOnce();
          markQueued(operation);
          trackPhase(tracked, operation, 'queued');
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
          const transient = await transientOutcome(operation, first, attempt);
          if (transient) return transient;
          // A consumer refused for a missing reference before it reached the loop: retain
          // the operation (a producer executed first keeps the error path: its consumers
          // already ran).
          if (code === MISSING_REF_ERROR && !producerFirst.has(operation) && DEFER_MISSING_REFS && pendingIntentsAccepting()) {
            const { resolvable: missing, echoes } = splitEchoIds(unresolvedIdsOf(first));
            if (echoes.length > 0) {
              // B12: an unresolved echo id has no producer that can still land (it leaked
              // from another capture window, A9, or its producer failed): retaining the
              // operation would park it until expiry. Fail it, visibly.
              logApp.error('[CHUNK-INTAKE] Operation refused: unresolved echo id (no producer in its chunk)', {
                chunk_id: message.chunk_id, object_id: operation.object_id, echoes, missing,
              });
              operationsCounter?.add(1, { outcome: 'echo_unresolved' });
              return { error: `unresolved echo id: ${echoes.join(', ')}` };
            }
            const retained = await deferOperation({ operation, envelope: envelopeOf(message), user, missing });
            if (retained) {
              logApp.info('[CHUNK-INTAKE] Operation retained (missing reference outside the loop)', {
                chunk_id: message.chunk_id, object_id: operation.object_id, missing,
              });
              return { deferred: true };
            }
          }
          return { error: String(first.message) };
        }
        if (operation.echo_id && producerFirst.has(operation)) {
          const root: any = result.data ? Object.values(result.data)[0] : undefined;
          if (root?.id) resolved.set(operation.echo_id, String(root.id));
        }
        return {};
      } catch (e: any) {
        const transient = await transientOutcome(operation, e, attempt);
        if (transient) return transient;
        return { error: String(e.message ?? e) };
      } finally {
        releaseOnce();
        trackPhase(tracked, operation, 'settled');
      }
    };
    // deferred === false is the retry sentinel of transientOutcome: loop until a real outcome
    const runOperation = async (operation: ChunkOperation): Promise<OperationOutcome> => {
      for (let attempt = 0; ; attempt += 1) {
        const outcome = await runOperationOnce(operation, attempt);
        if (outcome.deferred !== false) return outcome;
      }
    };
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
    const producerRuns = producers.map((operation) => runOperation(operation).finally(() => markQueued(operation)));
    await Promise.all(producerGates);
    const consumerRuns = consumers.map((operation) => runOperation(operation));
    const restErrors = await Promise.all([...producerRuns, ...consumerRuns]);
    const ordered = [...first, ...producers, ...consumers];
    const results = [...firstErrors, ...restErrors];
    for (let index = 0; index < ordered.length; index += 1) {
      await reportChunkOutcome(context, user, message, ordered[index], results[index]);
    }
    controls.ack();
    inFlightChunks.delete(attemptKey);
    transientAttempts.delete(attemptKey);
    chunksCounter?.add(1, { outcome: 'acked' });
    objectsCounter?.add(new Set(operations.map((operation) => operation.object_id).filter((id) => !!id)).size);
    chunkSeconds?.record((Date.now() - start) / 1000);
  } catch (e: any) {
    inFlightChunks.delete(attemptKey);
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
  startPreLoopTicker();
  startStallWatchdog();
  // Terminal outcome of a retained creation: meet the work expectation the chunk skipped
  // (applied), or meet it with an error (expired / failed), so works stay exact.
  registerPendingIntentSettled(async (record, error) => {
    if (!record.work_id) return;
    const settleContext = executionContext(CHUNK_INTAKE_MANAGER_CONTEXT);
    await reportExpectation(settleContext, SYSTEM_USER, record.work_id, error ? { error, source: 'chunk intake (retained creation)' } : undefined);
  });
  // Re-execution of a retained OPERATION: a fresh chunk context (the writer resolved from
  // the envelope, so no SYSTEM_USER divergence after a restart), the same in-process
  // executor. Outcomes: landed, handed to the loop (retained as an intent), still missing
  // (re-deferred here, attempts + 1), or a terminal failure (thrown, visible).
  registerPendingOperationExecute(async (record) => {
    const operation: ChunkOperation = JSON.parse(record.input_json);
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
  await registerChunkIntakeQueue();
  const consumer: ChunkConsumer = await consumeChunkIntakeQueue(PREFETCH, (payload: string, controls: ChunkControls) => {
    processChunkMessage(payload, controls).catch((e) => {
      logApp.error('[CHUNK-INTAKE] Unexpected chunk handling error', { cause: e });
    });
  });
  logApp.info('[OPENCTI-MODULE] Chunk intake manager consuming', {
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
