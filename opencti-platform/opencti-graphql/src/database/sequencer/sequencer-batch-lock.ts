// POC ingestion sequencer (plan 0009, Stage D4). Holder for the CURRENT batch lock, read by
// the middleware lock call sites at acquisition time. The loop applies intents one at a time
// (concurrency 1), so a module-level current lock is unambiguous. This module has zero
// imports on purpose: master-lock and middleware can use it without any cycle risk.
export interface SequencerBatchLock {
  heldKeys: Set<string>;
  signal: AbortSignal;
}

let current: SequencerBatchLock | null = null;

export const setCurrentBatchLock = (lock: SequencerBatchLock | null) => {
  current = lock;
};

export const getCurrentBatchLock = (): SequencerBatchLock | null => current;
