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
  // s9.12.3 strip-and-reconcile, aggressive variant: unresolved OPTIONAL refs never reject
  // the write (no reject-twice-then-silent-drop): the edge is recorded as a pending ref and
  // re-asserted when the target lands. Design: work-kb note opencti-strip-and-reconcile-design.
  stripReconcile: boolean;
  // Rung 5 increment 1: warm the NEXT batch's identity-map entries (elFindByIds + diff
  // basis) while the CURRENT batch awaits its commit bulk. The loop is wall-saturated but
  // await-bound (~97% wall, ~65% CPU measured 2026-09-10): the commit await is free time.
  // Warm-up only: per-batch state (absence cache, dedup prefetch) is NOT computed ahead,
  // and the end-of-batch evict/clear still runs after the warm, wiping anything stale.
  resolveAhead: boolean;
  applyConcurrency: number;
  preresolveIdsPerSearch: number;
  dedupPrefetchConcurrency: number;
  dedupPrefetchMsearch: boolean;
  dedupPrefetchMsearchSize: number;
  writtenIndex: boolean;
  pendingRefExpiryS: number;
  // s9.8.2 bounded member wait: plan passes spent waiting for a declared in-bundle member
  // before the ref is declared dead. With strip_reconcile on, a dead strip is recorded and
  // reconciled (verdict 31 fix): the limit is a latency knob, not a data-loss knob; 0 =
  // strip-and-record immediately, no member parking at all.
  memberWaitLimit: number;
  deferredWaitTtlMs: number;
  deferredWaitMaxExpiries: number;
  deferredReadmitRatio: number;
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
    // 600 (was 200, then 400 on the bench): the batch cap is the depth lever of the chunk path;
    // b400 read +10% over b200 on the full mix (2026-09-24), b600 neutral vs b400 on mix140k
    // (ladders of 2026-09-25: admission limits the batch at ~340 before the cap does).
    maxBatchSize: Number(conf.get('app:ingestion_sequencer:max_batch_size') ?? 600),
    maxBatchBytes: Number(conf.get('app:ingestion_sequencer:max_batch_bytes') ?? 8388608),
    gatherWindowMs: Number(conf.get('app:ingestion_sequencer:gather_window_ms') ?? 0),
    parkDeadlineMs: Number(conf.get('app:ingestion_sequencer:park_deadline_ms') ?? 5000),
    // 40000 / 256 MiB (was 2000, then 10000 / 64 MiB): a safety bound must sit well above any
    // offered concurrency; 2000 was hit twice (w16/P=6 HTTP, chunk prefetch 48) and 10000 on
    // every b400 anchor of the 2026-09-25 ladders (queue max 9,999), each time throttling the
    // loop instead of protecting anything. Memory is guarded by queue_max_bytes.
    queueMaxIntents: Number(conf.get('app:ingestion_sequencer:queue_max_intents') ?? 40000),
    queueMaxBytes: Number(conf.get('app:ingestion_sequencer:queue_max_bytes') ?? 268435456),
    identityMapSize: Number(conf.get('app:ingestion_sequencer:identity_map_size') ?? 200000),
    identityMapTtlS: Number(conf.get('app:ingestion_sequencer:identity_map_ttl_s') ?? 600),
    coalesceUpdateEvents: booleanConf('app:ingestion_sequencer:coalesce_update_events', true),
    // P3 (plan 0009 part 9): push whole bundles to the worker (bundle_inline marker), which
    // imports them in place by nb_deps levels; batch depth then comes from the payload.
    bundleIntake: booleanConf('app:ingestion_sequencer:bundle_intake', false),
    // D2 v3 soft-ref parking, off by default: measured to deadlock against a bounded
    // prefetch window (plan 0009 §8.8); default = v2 (hard endpoint deps only).
    parkSoftRefs: booleanConf('app:ingestion_sequencer:park_soft_refs', false),
    stripReconcile: booleanConf('app:ingestion_sequencer:strip_reconcile', false),
    resolveAhead: booleanConf('app:ingestion_sequencer:resolve_ahead', false),
    // rung 5 (2026-09-21): concurrent apply of independent groups within a batch, level by
    // level on the plan's dependsOn edges; 1 = the sequential path measured through the study.
    // Default 8 since 2026-09-25 (the operating point of every run since 2026-09-21; 16 stalled
    // once and buys nothing with the platform's single core saturated).
    applyConcurrency: Math.max(1, Math.floor(Number(conf.get('app:ingestion_sequencer:apply_concurrency') ?? 8))),
    // bounded search packets (2026-09-25): the batch pre-resolution (and resolve-ahead) resolves
    // its missing ids and loads its upsert targets N ids per search, one search at a time;
    // 0 = one call for the whole batch (elFindByIds' own grouping), the behaviour measured so far
    preresolveIdsPerSearch: Math.max(0, Math.floor(Number(conf.get('app:ingestion_sequencer:preresolve_ids_per_search') ?? 0))),
    // concurrent relation dedup prefetch searches per batch (was a constant 8)
    dedupPrefetchConcurrency: Math.max(1, Math.floor(Number(conf.get('app:ingestion_sequencer:dedup_prefetch_concurrency') ?? 8))),
    // msearch form of the dedup prefetch (2026-09-25): packets of N queries per engine round
    // trip, dedup_prefetch_concurrency of them run at once engine-side; off = one search each
    dedupPrefetchMsearch: booleanConf('app:ingestion_sequencer:dedup_prefetch_msearch', false),
    dedupPrefetchMsearchSize: Math.max(1, Math.floor(Number(conf.get('app:ingestion_sequencer:dedup_prefetch_msearch_size') ?? 200))),
    // written index (2026-09-21): the running batch's own writes are served first and kept
    // through mid-batch invalidations until commit (in-batch read-your-writes). Off through the
    // study's measurements (neutral then); ON since 2026-09-24 with the single wave per chunk,
    // where producers and consumers share a batch: it closed 60% of the soft refs stripped at
    // apply on MITRE (207 to 87) and brought the run from 295 to 353 obj/s (legacy wave 391).
    writtenIndex: booleanConf('app:ingestion_sequencer:identity_map_written_index', true),
    pendingRefExpiryS: Number(conf.get('app:ingestion_sequencer:pending_ref_expiry_s') ?? 604800),
    memberWaitLimit: Number(conf.get('app:ingestion_sequencer:member_wait_limit') ?? 2),
    // B10 (2026-09-16): a deferral waiting on a queued producer is re-admitted when the
    // producer lands or fails; the TTL bounds a missed wake (30 s >> the deepest queue wait
    // measured, 7 s at prefetch 512), and after max expiries the intent applies as-is.
    deferredWaitTtlMs: Number(conf.get('app:ingestion_sequencer:deferred_wait_ttl_ms') ?? 30000),
    deferredWaitMaxExpiries: Number(conf.get('app:ingestion_sequencer:deferred_wait_max_expiries') ?? 3),
    // share of the batch cap that lane re-admissions may take per cycle (the rest is kept
    // for the queue drain); the queue also gets at least this share of the cap every cycle
    deferredReadmitRatio: Number(conf.get('app:ingestion_sequencer:deferred_readmit_ratio') ?? 0.5),
    origin: conf.get('app:ingestion_sequencer:origin') ?? 'worker',
  };
};

export const SEQUENCER_CONFIG: SequencerConfig = readConfig();

export const isSequencerEnabled = () => SEQUENCER_CONFIG.enabled;

if (SEQUENCER_CONFIG.enabled) {
  logApp.info('[SEQUENCER] Ingestion sequencer enabled', { ...SEQUENCER_CONFIG });
}
