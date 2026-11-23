import { afterEach, describe, expect, it } from 'vitest';
import conf from '../../../src/config/conf';
import { SEQUENCER_CONFIG, isSequencerEnabled, numberConf } from '../../../src/database/sequencer/sequencer-config';

describe('sequencer configuration defaults', () => {
  it('should be disabled by default with passthrough mode', () => {
    expect(isSequencerEnabled()).toBe(false);
    expect(SEQUENCER_CONFIG.mode).toBe('passthrough');
  });
  it('should expose the product defaults (plan 0009 A2, revised 2026-09-25)', () => {
    expect(SEQUENCER_CONFIG.maxBatchSize).toBe(600); // 200 -> 600 (2026-09-25, chunk path operating point)
    expect(SEQUENCER_CONFIG.maxBatchBytes).toBe(8388608);
    expect(SEQUENCER_CONFIG.gatherWindowMs).toBe(0);
    expect(SEQUENCER_CONFIG.parkDeadlineMs).toBe(5000);
    expect(SEQUENCER_CONFIG.queueMaxIntents).toBe(40000); // 2000 -> 10000 (2026-09-14) -> 40000 (2026-09-25), each bound was hit
    expect(SEQUENCER_CONFIG.queueMaxBytes).toBe(268435456);
    expect(SEQUENCER_CONFIG.applyConcurrency).toBe(8); // 1 -> 8 (2026-09-25)
    expect(SEQUENCER_CONFIG.writtenIndex).toBe(true); // on since 2026-09-24 (single wave per chunk)
    expect(SEQUENCER_CONFIG.identityMapSize).toBe(200000);
    expect(SEQUENCER_CONFIG.identityMapTtlS).toBe(600);
    expect(SEQUENCER_CONFIG.coalesceUpdateEvents).toBe(true);
    expect(SEQUENCER_CONFIG.origin).toBe('worker');
    // B10 deferred lanes with wake-up (2026-09-16)
    expect(SEQUENCER_CONFIG.deferredWaitTtlMs).toBe(30000);
    expect(SEQUENCER_CONFIG.deferredWaitMaxExpiries).toBe(3);
    expect(SEQUENCER_CONFIG.deferredReadmitRatio).toBe(0.5);
  });
  it('should keep the no-op tag caps off by default, ratio 5 (task 0040)', () => {
    expect(SEQUENCER_CONFIG.noopTagCaps).toBe(false);
    expect(SEQUENCER_CONFIG.noopTagCeilingRatio).toBe(5);
  });
  it('should keep the append buffer on by default, on external references, flushed every 15 s (task 0040)', () => {
    expect(SEQUENCER_CONFIG.denormBuffer).toBe(true);
    expect(SEQUENCER_CONFIG.denormBufferRelations).toEqual(['external-reference']);
    expect(SEQUENCER_CONFIG.denormFlushPeriodMs).toBe(15000);
    expect(SEQUENCER_CONFIG.denormFlushTargetMaxIds).toBe(5000);
    expect(SEQUENCER_CONFIG.denormBufferMaxIds).toBe(1000000);
  });
});

describe('sequencer numeric knobs (task 0040 numberConf)', () => {
  const KEY = 'app:ingestion_sequencer:test_number_knob';
  afterEach(() => {
    conf.set(KEY, undefined);
  });

  it('should fall back to the default when the knob is absent, empty or not a number, and hold it at its minimum', () => {
    expect(numberConf(KEY, 15000, 100)).toBe(15000);
    conf.set(KEY, '');
    expect(numberConf(KEY, 15000, 100), 'an empty environment variable is not 0').toBe(15000);
    conf.set(KEY, 'fifteen');
    expect(numberConf(KEY, 15000, 100)).toBe(15000);
    conf.set(KEY, '5');
    expect(numberConf(KEY, 15000, 100)).toBe(100);
    conf.set(KEY, '2500');
    expect(numberConf(KEY, 15000, 100)).toBe(2500);
  });
});
