// POC ingestion sequencer (plan 0009, Stage B3/B5). Pass-through loop: a single async loop per
// process takes intents in round-robin order and applies each through the UNCHANGED direct path,
// awaiting completion before the next (concurrency 1). No cache, no buffers: this measures the
// sequential floor. Errors are caught per intent and rejected on its promise, so pycti sees the
// same GraphQL errors as today (MissingReferenceError, LockTimeoutError, validation errors...).
// Fail-open watchdog (B5): if the loop ever dies, submit falls back to the direct path and logs.
// Stage C replaces the loop body with batch formation; the submit/queue contract stays.
import { logApp } from '../../config/conf';
import { SEQUENCER_CONFIG } from './sequencer-config';
import { sequencerMetrics } from './sequencer-metrics';
import { SequencerQueue } from './sequencer-queue';
import { buildIntent } from './sequencer-intent';
import type { IntentKind } from './sequencer-intent';
import type { AuthContext, AuthUser } from '../../types/user';

const queue = new SequencerQueue();
let loopStarted = false;
let loopDead = false;

export const isSequencerLoopAlive = () => loopStarted && !loopDead;

const runLoop = async () => {
  if (SEQUENCER_CONFIG.mode === 'batch') {
    // Stage B ships pass-through only; the batch loop lands in Stage C.
    logApp.warn('[SEQUENCER] mode=batch not implemented yet, running pass-through');
  }
  logApp.info('[SEQUENCER] pass-through loop started');
  for (;;) {
    const intent = await queue.take();
    sequencerMetrics.queueWait((Date.now() - intent.arrivedAt) / 1000);
    const t0 = Date.now();
    try {
      const result = await intent.apply();
      sequencerMetrics.intent('applied');
      intent.resolve(result);
    } catch (err) {
      sequencerMetrics.intent('failed');
      intent.reject(err);
    }
    sequencerMetrics.phase('apply', (Date.now() - t0) / 1000);
  }
};

const ensureLoop = () => {
  if (loopStarted) return;
  loopStarted = true;
  runLoop().catch((err) => {
    // The loop only awaits queue.take() and the guarded apply: reaching here is a bug. Fail open:
    // every later submit takes the direct path, ingestion continues without the sequencer.
    loopDead = true;
    logApp.error('[SEQUENCER] loop died, failing open to the direct path', { cause: err });
  });
};

interface SubmitArgs {
  kind: IntentKind;
  type: string;
  input: Record<string, any>;
  opts: Record<string, any>;
  candidateIds: string[];
  apply: () => Promise<any>;
}

// Called by the boundary (middleware.ts) AFTER isSequencerEligible returned true. The apply
// closure wraps the direct implementation with the re-entrancy-marked context.
export const submitIntent = async (context: AuthContext, user: AuthUser, args: SubmitArgs): Promise<any> => {
  if (loopDead) {
    sequencerMetrics.intent('bypassed');
    return args.apply();
  }
  ensureLoop();
  const intent = buildIntent({ ...args, user, context });
  await queue.put(intent);
  return intent.promise;
};
