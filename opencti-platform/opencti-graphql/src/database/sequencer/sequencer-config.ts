// POC ingestion sequencer (plan 0009, Stage A). Configuration knobs only: nothing is wired
// into the write path at this stage. With app:ingestion_sequencer:enabled=false (the default)
// the platform behaves exactly as its base commit, which provides the control run on the same
// build. Knob semantics: plan 0009 §2.6 (the size caps are safety bounds sitting above the
// structural ceiling = offered worker concurrency; the gather window only matters at mid-load).
import conf, { booleanConf, logApp } from '../../config/conf';

export type SequencerMode = 'passthrough' | 'batch';

export interface SequencerConfig {
  enabled: boolean;
  mode: SequencerMode;
  maxBatchSize: number;
  maxBatchBytes: number;
  gatherWindowMs: number;
  parkDeadlineMs: number;
  queueMaxIntents: number;
  queueMaxBytes: number;
  identityMapSize: number;
  identityMapTtlS: number;
  coalesceUpdateEvents: boolean;
  bundleIntake: boolean;
  parkSoftRefs: boolean;
  origin: string;
}

const readConfig = (): SequencerConfig => {
  const mode = conf.get('app:ingestion_sequencer:mode') ?? 'passthrough';
  if (mode !== 'passthrough' && mode !== 'batch') {
    throw new Error(`Invalid app:ingestion_sequencer:mode "${mode}" (expected passthrough | batch)`);
  }
  return {
    enabled: booleanConf('app:ingestion_sequencer:enabled', false),
    mode,
    maxBatchSize: Number(conf.get('app:ingestion_sequencer:max_batch_size') ?? 200),
    maxBatchBytes: Number(conf.get('app:ingestion_sequencer:max_batch_bytes') ?? 8388608),
    gatherWindowMs: Number(conf.get('app:ingestion_sequencer:gather_window_ms') ?? 0),
    parkDeadlineMs: Number(conf.get('app:ingestion_sequencer:park_deadline_ms') ?? 5000),
    queueMaxIntents: Number(conf.get('app:ingestion_sequencer:queue_max_intents') ?? 2000),
    queueMaxBytes: Number(conf.get('app:ingestion_sequencer:queue_max_bytes') ?? 67108864),
    identityMapSize: Number(conf.get('app:ingestion_sequencer:identity_map_size') ?? 200000),
    identityMapTtlS: Number(conf.get('app:ingestion_sequencer:identity_map_ttl_s') ?? 600),
    coalesceUpdateEvents: booleanConf('app:ingestion_sequencer:coalesce_update_events', true),
    // P3 (plan 0009 part 9): push whole bundles to the worker (bundle_inline marker), which
    // imports them in place by nb_deps levels; batch depth then comes from the payload.
    bundleIntake: booleanConf('app:ingestion_sequencer:bundle_intake', false),
    // D2 v3 soft-ref parking, off by default: measured to deadlock against a bounded
    // prefetch window (plan 0009 §8.8); default = v2 (hard endpoint deps only).
    parkSoftRefs: booleanConf('app:ingestion_sequencer:park_soft_refs', false),
    origin: conf.get('app:ingestion_sequencer:origin') ?? 'worker',
  };
};

export const SEQUENCER_CONFIG: SequencerConfig = readConfig();

export const isSequencerEnabled = () => SEQUENCER_CONFIG.enabled;

if (SEQUENCER_CONFIG.enabled) {
  logApp.info('[SEQUENCER] Ingestion sequencer enabled', { ...SEQUENCER_CONFIG });
}
