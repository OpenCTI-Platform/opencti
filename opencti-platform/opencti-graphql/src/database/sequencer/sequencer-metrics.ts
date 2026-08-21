// POC ingestion sequencer (plan 0009, Stage A). Dedicated OTel instruments, exported on the
// same MeterProvider (and thus the same Prometheus endpoint) as the platform metrics. Kept in
// a separate module so the POC surface on shared files stays minimal.
import { ValueType } from '@opentelemetry/api';
import type { Counter, Gauge, Histogram } from '@opentelemetry/api';
import { meterManager } from '../../config/tracing';

export type IntentOutcome = 'applied' | 'coalesced' | 'parked' | 'expired' | 'failed' | 'bypassed';
export type BatchPhase = 'resolve' | 'order' | 'apply' | 'commit' | 'events';
export type MapEvent = 'hit' | 'miss' | 'evict' | 'invalidate';

class SequencerMetrics {
  private intents: Counter | null = null;

  private batches: Counter | null = null;

  private batchSize: Histogram | null = null;

  private batchPhaseSeconds: Histogram | null = null;

  private identityMap: Counter | null = null;

  private parkSeconds: Histogram | null = null;

  private queueDepthGauge: Gauge | null = null;

  private queueWaitSeconds: Histogram | null = null;

  private esOps: Counter | null = null;

  private sidewritesGrouped: Counter | null = null;

  private eventsCoalesced: Counter | null = null;

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
      description: 'Intents per committed batch',
      advice: { explicitBucketBoundaries: [1, 2, 4, 8, 16, 32, 64, 128, 200] },
    });
    this.batchPhaseSeconds = meter.createHistogram('opencti_sequencer_batch_phase_seconds', {
      valueType: ValueType.DOUBLE,
      description: 'Batch phase duration in seconds (resolve, order, apply, commit, events)',
      advice: { explicitBucketBoundaries: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10] },
    });
    this.identityMap = meter.createCounter('opencti_sequencer_identity_map', {
      valueType: ValueType.INT,
      description: 'Identity map events (hit, miss, evict, invalidate)',
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
  }

  intent(outcome: IntentOutcome, count = 1) {
    this.intents?.add(count, { outcome });
  }

  batchCommitted(size: number) {
    this.batches?.add(1);
    this.batchSize?.record(size);
  }

  phase(phase: BatchPhase, seconds: number) {
    this.batchPhaseSeconds?.record(seconds, { phase });
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

  queueWait(seconds: number) {
    this.queueWaitSeconds?.record(seconds);
  }

  esOp(op: 'search' | 'bulk_docs' | 'bulk_side' | 'refresh', count = 1) {
    this.esOps?.add(count, { op });
  }

  sidewriteGrouped(count = 1) {
    this.sidewritesGrouped?.add(count);
  }

  eventCoalesced(count = 1) {
    this.eventsCoalesced?.add(count);
  }
}

export const sequencerMetrics = new SequencerMetrics();
sequencerMetrics.register();
