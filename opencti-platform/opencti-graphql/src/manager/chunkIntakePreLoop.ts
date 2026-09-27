// Chunk-queue intake: adaptive pre-loop admission gate (2026-09-24).
//
// The pre-loop permit bounds the operations of a chunk between "execution starts" and "the
// sequencer boundary has queued the intent": their pre-loop engine lookups (domain
// pre-resolves, observable lookups, cold identity-map resolves) are what overflowed the
// engine's search queue at intake start (1,633 rejections at w1 prefetch 128 without it).
// A fixed limit is wrong in both directions: 32 leaves a third to a half of the operations
// waiting in steady state (measured 2026-09-24: 35% on the full mix, 45% on MITRE, with
// zero engine rejection), and a higher fixed value re-opens the start-up burst.
//
// So the limit moves, AIMD style, on two signals the manager already sees:
//   - operations PACED by the current limit and no recent engine error: the limit grows
//     (multiplicative step, bounded by max); no paced operation, nothing to gain, hold;
//   - a transient ENGINE error on any operation (rejected execution, circuit breaker,
//     429 / 503, connection reset): the limit is halved at the next tick, and halved again
//     at every following tick that still sees errors, down to min; growth resumes only
//     after a quiet window without errors.
// The gate is pure (injected clock, explicit tick) so the policy is unit-tested; the manager
// wires the timer, the metrics and the error signal.
export interface PreLoopGateOptions {
  // initial limit; 0 disables the gate entirely (acquire never waits)
  initial: number;
  min: number;
  max: number;
  adaptive: boolean;
  // fraction of the current limit added per growing tick (at least one permit)
  increaseRatio: number;
  // no engine error for this long before the limit may grow again
  quietMs: number;
  now?: () => number;
  onLimitChange?: (limit: number, direction: 'up' | 'down') => void;
}

export class PreLoopGate {
  private readonly opts: PreLoopGateOptions;

  private limit: number;

  private inUse = 0;

  private waiters: (() => void)[] = [];

  private pacedSinceTick = 0;

  private errorsSinceTick = 0;

  private lastErrorAt = Number.NEGATIVE_INFINITY;

  constructor(opts: PreLoopGateOptions) {
    this.opts = opts;
    const floor = Math.max(1, Math.floor(opts.min));
    const ceiling = Math.max(floor, Math.floor(opts.max));
    this.limit = Math.min(ceiling, Math.max(floor, Math.floor(opts.initial)));
  }

  enabled(): boolean {
    return this.opts.initial > 0;
  }

  currentLimit(): number {
    return this.limit;
  }

  inFlight(): number {
    return this.inUse;
  }

  waiting(): number {
    return this.waiters.length;
  }

  // Resolves with false when a permit was free, true when the caller had to wait (paced).
  async acquire(): Promise<boolean> {
    if (!this.enabled()) return false;
    if (this.inUse < this.limit) {
      this.inUse += 1;
      return false;
    }
    this.pacedSinceTick += 1;
    await new Promise<void>((resolve) => this.waiters.push(resolve));
    return true; // the permit was handed over by drainWaiters
  }

  release() {
    if (!this.enabled()) return;
    this.inUse = Math.max(0, this.inUse - 1);
    this.drainWaiters();
  }

  // Any transient engine error seen by an operation, whatever the retry decision.
  onEngineError() {
    this.errorsSinceTick += 1;
    this.lastErrorAt = (this.opts.now ?? Date.now)();
  }

  // One evaluation of the policy over the events since the previous tick.
  tick() {
    const errors = this.errorsSinceTick;
    const paced = this.pacedSinceTick;
    this.errorsSinceTick = 0;
    this.pacedSinceTick = 0;
    if (!this.enabled() || !this.opts.adaptive) return;
    const floor = Math.max(1, Math.floor(this.opts.min));
    const ceiling = Math.max(floor, Math.floor(this.opts.max));
    if (errors > 0) {
      const next = Math.max(floor, Math.floor(this.limit / 2));
      if (next < this.limit) {
        this.limit = next;
        this.opts.onLimitChange?.(this.limit, 'down');
      }
      return;
    }
    if (paced === 0 || this.limit >= ceiling) return;
    const now = (this.opts.now ?? Date.now)();
    if (now - this.lastErrorAt < this.opts.quietMs) return;
    const step = Math.max(1, Math.ceil(this.limit * this.opts.increaseRatio));
    this.limit = Math.min(ceiling, this.limit + step);
    this.opts.onLimitChange?.(this.limit, 'up');
    this.drainWaiters();
  }

  private drainWaiters() {
    while (this.waiters.length > 0 && this.inUse < this.limit) {
      const next = this.waiters.shift() as () => void;
      this.inUse += 1;
      next();
    }
  }
}
