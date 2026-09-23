import { describe, expect, it } from 'vitest';
import { SEQUENCER_CONFIG, isSequencerEnabled } from '../../../src/database/sequencer/sequencer-config';

describe('sequencer configuration defaults', () => {
  it('should be disabled by default with passthrough mode', () => {
    expect(isSequencerEnabled()).toBe(false);
    expect(SEQUENCER_CONFIG.mode).toBe('passthrough');
  });
  it('should expose the plan 0009 A2 defaults', () => {
    expect(SEQUENCER_CONFIG.maxBatchSize).toBe(200);
    expect(SEQUENCER_CONFIG.maxBatchBytes).toBe(8388608);
    expect(SEQUENCER_CONFIG.gatherWindowMs).toBe(0);
    expect(SEQUENCER_CONFIG.parkDeadlineMs).toBe(5000);
    expect(SEQUENCER_CONFIG.queueMaxIntents).toBe(10000); // raised 2026-09-14 (2000 throttled the loop twice)
    expect(SEQUENCER_CONFIG.queueMaxBytes).toBe(67108864);
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
