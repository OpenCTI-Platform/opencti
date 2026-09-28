import { describe, expect, it } from 'vitest';
import { SEQUENCER_CONFIG, isSequencerEnabled } from '../../../src/database/sequencer/sequencer-config';

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
});
