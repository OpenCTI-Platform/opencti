// POC ingestion sequencer (plan 0009, Stage A). Dedicated OTel instruments, exported on the
// same MeterProvider (and thus the same Prometheus endpoint) as the platform metrics. Kept in
// a separate module so the POC surface on shared files stays minimal.
import { ValueType } from '@opentelemetry/api';
import type { Counter, Gauge, Histogram } from '@opentelemetry/api';
import { meterManager } from '../../config/tracing';

export type IntentOutcome = 'applied' | 'coalesced' | 'parked' | 'expired' | 'failed' | 'bypassed' | 'deferred' | 'retained';
export type BatchPhase = 'resolve' | 'order' | 'apply' | 'commit' | 'events' | 'resolve_ahead';
export type MapEvent = 'hit' | 'miss' | 'evict' | 'invalidate' | 'absent' | 'written_hit' | 'written_shielded';

class SequencerMetrics {
  private intents: Counter | null = null;

  private batches: Counter | null = null;

  private batchSize: Histogram | null = null;

  private batchPhaseSeconds: Histogram | null = null;

  private applyLevelsHist: Histogram | null = null;

  private identityMap: Counter | null = null;

  private parkSeconds: Histogram | null = null;

  private queueDepthGauge: Gauge | null = null;

  private queueBytesGauge: Gauge | null = null;

  private queueWaitSeconds: Histogram | null = null;

  private esOps: Counter | null = null;

  private sidewritesGrouped: Counter | null = null;

  private eventsCoalesced: Counter | null = null;

  private pendingRefs: Counter | null = null;

  private pendingIntents: Counter | null = null;

  private chainStepsCounter: Counter | null = null;

  private deferReasons: Counter | null = null;

  private memberDeadCounter: Counter | null = null;

  private memberDeadStrippedCounter: Counter | null = null;

  private rootFailures: Counter | null = null;

  private missingRefOrigins: Counter | null = null;

  private lockEscapes: Counter | null = null;

  private searchCallers: Counter | null = null;

  private batchDependsOnEdges: Histogram | null = null;

  private lanesGauge: Gauge | null = null;

  private lanesWaitingGauge: Gauge | null = null;

  private laneEvents: Counter | null = null;

  private batchDistinctSources: Histogram | null = null;

  register() {
    const meter = meterManager.meterProvider.getMeter('opencti-sequencer');
    this.intents = meter.createCounter('opencti_sequencer_intents_total', {
      valueType: ValueType.INT,
      description: 'Intents by outcome (applied, coalesced, parked, expired, failed, bypassed)',
    });
    this.batches = meter.createCounter('opencti_sequencer_batches_total', {
      valueType: ValueType.INT,
      description: 'Committed batches',
    });
    this.batchSize = meter.createHistogram('opencti_sequencer_batch_size', {
      valueType: ValueType.INT,
      description: 'Intents assembled per batch cycle (fresh + released deferred + parked re-entries)',
      advice: { explicitBucketBoundaries: [1, 2, 4, 8, 16, 32, 64, 128, 200] },
    });
    this.batchPhaseSeconds = meter.createHistogram('opencti_sequencer_batch_phase_seconds', {
      valueType: ValueType.DOUBLE,
      description: 'Batch phase duration in seconds (resolve, order, apply, commit, events)',
      advice: { explicitBucketBoundaries: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10] },
    });
    this.applyLevelsHist = meter.createHistogram('opencti_sequencer_apply_levels', {
      valueType: ValueType.INT,
      description: 'Dependency levels applied per batch when apply_concurrency > 1 (1 = every group independent)',
      advice: { explicitBucketBoundaries: [1, 2, 3, 4, 6, 8, 12, 16, 24] },
    });
    this.identityMap = meter.createCounter('opencti_sequencer_identity_map', {
      valueType: ValueType.INT,
      description: 'Identity map events (hit, miss, evict, invalidate; absent = served known-absent from the s10.3 batch negative cache, one avoided ES search each)',
    });
    this.parkSeconds = meter.createHistogram('opencti_sequencer_park_seconds', {
      valueType: ValueType.DOUBLE,
      description: 'Time an intent spent parked before resolution or expiry',
      advice: { explicitBucketBoundaries: [0.05, 0.1, 0.25, 0.5, 1, 2, 5] },
    });
    this.queueDepthGauge = meter.createGauge('opencti_sequencer_queue_depth', {
      valueType: ValueType.INT,
      description: 'Intents queued at batch formation time',
    });
    // queue_max_bytes was blind (2026-09-15): the count bound is visible through the depth
    // gauge, the bytes bound was not. Deep prefetch rungs (past 128) need both.
    this.lanesGauge = meter.createGauge('opencti_sequencer_deferred_lanes', {
      valueType: ValueType.INT,
      description: 'Deferred lanes (one FIFO per target) at batch assembly',
    });
    this.lanesWaitingGauge = meter.createGauge('opencti_sequencer_deferred_waiting', {
      valueType: ValueType.INT,
      description: 'Deferred intents waiting on a queued or deferred producer (B10 wake-up)',
    });
    this.laneEvents = meter.createCounter('opencti_sequencer_lane_events_total', {
      valueType: ValueType.INT,
      description: 'Deferred-lane events by kind (registered, woken_landed, woken_failed, expired, exhausted, readmitted, skipped)',
    });
    this.queueBytesGauge = meter.createGauge('opencti_sequencer_queue_bytes', {
      valueType: ValueType.INT,
      description: 'Bytes of intents queued (queue_max_bytes is the bound)',
    });
    this.queueWaitSeconds = meter.createHistogram('opencti_sequencer_queue_wait_seconds', {
      valueType: ValueType.DOUBLE,
      description: 'Time an intent waited in the queue before entering a batch',
      advice: { explicitBucketBoundaries: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5] },
    });
    this.esOps = meter.createCounter('opencti_sequencer_es_ops_total', {
      valueType: ValueType.INT,
      description: 'ES operations issued by the sequencer, by op (search, bulk_docs, bulk_side, refresh)',
    });
    this.sidewritesGrouped = meter.createCounter('opencti_sequencer_sidewrites_grouped_total', {
      valueType: ValueType.INT,
      description: 'Denormalization side-writes merged into an existing per-document update (E1 grouping)',
    });
    this.eventsCoalesced = meter.createCounter('opencti_sequencer_events_coalesced_total', {
      valueType: ValueType.INT,
      description: 'Update events merged into a per-entity batch event (E8, coalesce_update_events)',
    });
    this.pendingIntents = meter.createCounter('opencti_sequencer_pending_intents_total', {
      valueType: ValueType.INT,
      description: 'Retained creations (hard-ref retention) by event (deferred, redeferred, resubmitted, applied, expired, failed)',
    });
    this.pendingRefs = meter.createCounter('opencti_sequencer_pending_refs_total', {
      valueType: ValueType.INT,
      description: 'Strip-and-reconcile events, by kind (stripped, reconciled, expired)',
    });
    this.chainStepsCounter = meter.createCounter('opencti_sequencer_chain_steps_total', {
      valueType: ValueType.INT,
      description: 'Same-target applications chained behind a previous write in the same batch (P2 merge-fold, steps beyond each chain head)',
    });
    this.deferReasons = meter.createCounter('opencti_sequencer_defer_reasons_total', {
      valueType: ValueType.INT,
      description: 'Deferrals by reason (P2 residual reasons + s9.8 certainty reasons queued_producer/member_wait)',
    });
    this.lockEscapes = meter.createCounter('opencti_sequencer_lock_escapes_total', {
      valueType: ValueType.INT,
      description: 'Lock keys asked by an apply-time lock site and not held by the batch lock (a real lock was taken), by key kind; fix 2026-09-22 instrumentation',
    });
    this.missingRefOrigins = meter.createCounter('opencti_sequencer_missing_ref_origin_total', {
      valueType: ValueType.INT,
      description: 'Reference ids missing at apply, by origin (written_in_map, written_evicted, in_batch, outside) and outcome (parked, deferred, failed, final); written-index probe 2026-09-21',
    });
    this.memberDeadCounter = meter.createCounter('opencti_sequencer_member_dead_total', {
      valueType: ValueType.INT,
      description: 'Intents rejected final: an in-bundle ref whose producer never arrived (its creation failed), s9.8.2',
    });
    this.memberDeadStrippedCounter = meter.createCounter('opencti_sequencer_member_dead_stripped_total', {
      valueType: ValueType.INT,
      description: 'Dead SOFT member refs stripped from a surviving intent (the container applies without the impossible edge), s9.10.2',
    });
    this.rootFailures = meter.createCounter('opencti_sequencer_root_failures_total', {
      valueType: ValueType.INT,
      description: 'Apply failures with NO failed in-batch producer (cascade roots), by error code (s9.9.3)',
    });
    this.searchCallers = meter.createCounter('opencti_sequencer_search_callers_total', {
      valueType: ValueType.INT,
      description: 'ES searches by caller site (plan 0010 step 1); _all counts every elRawSearch (denominator), unlabeled = elFindByIds calls without a caller hint',
    });
    this.batchDependsOnEdges = meter.createHistogram('opencti_sequencer_batch_dependson_edges', {
      valueType: ValueType.INT,
      description: 'In-batch dependsOn edges per batch plan: dependents co-batched with their producers (the relatedness metric, plan 0009 s9.12.1)',
      advice: { explicitBucketBoundaries: [0, 1, 2, 4, 8, 16, 32, 64] },
    });
    this.batchDistinctSources = meter.createHistogram('opencti_sequencer_batch_distinct_sources', {
      valueType: ValueType.INT,
      description: 'Distinct intent sources (applicant ids) per batch: proxy for distinct bundles per batch while RabbitMQ prefetch=1 (one in-flight bundle per connector)',
      advice: { explicitBucketBoundaries: [1, 2, 3, 4, 6, 8, 12, 16] },
    });
  }

  intent(outcome: IntentOutcome, kind?: 'entity' | 'relation') {
    this.intents?.add(1, kind ? { outcome, kind } : { outcome });
  }

  batchCommitted(size: number) {
    this.batches?.add(1);
    this.batchSize?.record(size);
  }

  phase(phase: BatchPhase, seconds: number) {
    this.batchPhaseSeconds?.record(seconds, { phase });
  }

  applyLevels(levels: number) {
    this.applyLevelsHist?.record(levels);
  }

  mapEvent(event: MapEvent, count = 1) {
    this.identityMap?.add(count, { event });
  }

  parked(seconds: number) {
    this.parkSeconds?.record(seconds);
  }

  queueDepth(depth: number) {
    this.queueDepthGauge?.record(depth);
  }

  queueBytes(bytes: number) {
    this.queueBytesGauge?.record(bytes);
  }

  lanes(lanes: number, waiting: number) {
    this.lanesGauge?.record(lanes);
    this.lanesWaitingGauge?.record(waiting);
  }

  laneEvent(event: 'registered' | 'woken_landed' | 'woken_failed' | 'expired' | 'exhausted' | 'readmitted' | 'skipped', count = 1) {
    this.laneEvents?.add(count, { event });
  }

  queueWait(seconds: number) {
    this.queueWaitSeconds?.record(seconds);
  }

  esOp(op: 'search' | 'bulk_docs' | 'bulk_side' | 'refresh', count = 1) {
    this.esOps?.add(count, { op });
  }

  sidewriteGrouped(count = 1) {
    this.sidewritesGrouped?.add(count);
  }

  pendingIntentEvent(event: 'deferred' | 'redeferred' | 'resubmitted' | 'applied' | 'expired' | 'failed' | 'handed' | 'pending', count = 1) {
    this.pendingIntents?.add(count, { event });
  }

  pendingRefEvent(kind: 'stripped' | 'reconciled' | 'expired', count = 1) {
    this.pendingRefs?.add(count, { kind });
  }

  eventCoalesced(count = 1) {
    this.eventsCoalesced?.add(count);
  }

  chainSteps(count = 1) {
    this.chainStepsCounter?.add(count);
  }

  deferReason(reason: string) {
    this.deferReasons?.add(1, { reason });
  }

  missingRefOrigin(origin: string, outcome: string) {
    this.missingRefOrigins?.add(1, { origin, outcome });
  }

  lockEscape(kind: string, count = 1) {
    this.lockEscapes?.add(count, { kind });
  }

  memberDead(count = 1) {
    this.memberDeadCounter?.add(count);
  }

  memberDeadStripped(count = 1) {
    this.memberDeadStrippedCounter?.add(count);
  }

  rootFailure(code: string) {
    this.rootFailures?.add(1, { code });
  }

  searchCaller(caller: string, count = 1) {
    this.searchCallers?.add(count, { caller });
  }

  batchRelatedness(dependsOnEdges: number, distinctSources: number) {
    this.batchDependsOnEdges?.record(dependsOnEdges);
    this.batchDistinctSources?.record(distinctSources);
  }
}

export const sequencerMetrics = new SequencerMetrics();
sequencerMetrics.register();
