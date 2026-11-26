// POC ingestion sequencer, task 0040 lead 36: the parked set and the park clock of each intent.
//
// An intent parks while a reference it needs has no producer in sight, for at most one park deadline: the
// clock starts at its first park and travels with the intent (sequencer-intent.ts parkedAt / parkDeadline).
// Each way back into a batch keeps it: the parked set itself, a lane (a same-key companion sent there when
// its head left), a multi_writer carry, a failed-producer deferral, an apply failure on a missing reference.
// The deadline only counts while the intent waits in a park: leaving it (to apply, or to a lane with nothing
// blocking it) ends that wait; a later re-park finds the deadline kept and expires at once if it has passed.
// A deadline restarted on any of them let same-key relations hand the wait to each other: two connectors
// asserting one relationship 1 s apart waited 9 s, twenty of them up to 49 s (review 2026-11-25).
// Only a deferral on a wait with its own bound restarts it: a producer now queued (B10, lane TTL) or a declared
// member not seen yet (bounded attempts); cutting those at the park deadline applied too early.
// Once forced direct (deadline past, or a B10 lane wait exhausted), the intent stays expired whatever path
// brings it back, and applies as-is through the unchanged path.
// Pure bookkeeping, no I/O: the loop (sequencer-loop.ts) records the metrics from what each call returns.
import type { SequencerIntent } from './sequencer-intent';
import type { BatchPlan, DeferReason } from './sequencer-batch-plan';

const OWN_BOUND_WAITS: ReadonlySet<DeferReason> = new Set<DeferReason>(['queued_producer', 'member_wait']);

const restartClock = (intent: SequencerIntent) => {
  delete intent.parkDeadline;
  delete intent.parkedAt;
};

export class ParkBook {
  private parked: SequencerIntent[] = [];

  constructor(private readonly deadlineMs: number) {}

  size() {
    return this.parked.length;
  }

  intents(): readonly SequencerIntent[] {
    return this.parked;
  }

  nearestDeadline(): number | null {
    if (this.parked.length === 0) return null;
    return Math.min(...this.parked.map((intent) => intent.parkDeadline as number));
  }

  // the parked intents re-plan every cycle: they leave the set for the batch, the plan parks them again
  take(): SequencerIntent[] {
    const taken = this.parked;
    this.parked = [];
    return taken;
  }

  // forceDirect of a batch: expired before, past their park deadline now while waiting in a park (parkedAt set:
  // an intent that left its park to apply and comes back by a carry is not waiting for a reference any more), or
  // out of their B10 lane wait.
  // newlyExpired: the park deadlines that passed in this cycle (once per intent), with the wait since the park.
  expire(batch: SequencerIntent[], exhaustedIds: Set<string>, now: number) {
    const forceDirect = new Set<string>();
    const newlyExpired: { intent: SequencerIntent; waitedMs: number }[] = [];
    batch.forEach((intent) => {
      if (!intent.expired && intent.parkedAt !== undefined && intent.parkDeadline !== undefined && intent.parkDeadline <= now) {
        intent.expired = true;
        newlyExpired.push({ intent, waitedMs: now - (intent.parkedAt ?? now) });
        delete intent.parkedAt; // the wait is counted once
      } else if (!intent.expired && exhaustedIds.has(intent.id)) {
        intent.expired = true;
      }
      if (intent.expired) forceDirect.add(intent.id);
    });
    return { forceDirect, newlyExpired };
  }

  private park(intent: SequencerIntent, now: number, deadline = now + this.deadlineMs): boolean {
    const fresh = intent.parkDeadline === undefined;
    intent.parkDeadline ??= deadline;
    intent.parkedAt ??= now;
    this.parked.push(intent);
    return fresh;
  }

  // After the plan: park its parked intents on their clock, restart the clock of a deferral with its own bound.
  // fresh: the intents whose clock starts now; unparked: intents that leave their park wait (to apply, or to their
  // lane with nothing blocking them), with that wait.
  route(plan: Pick<BatchPlan, 'order' | 'deferred' | 'parked'>, now: number) {
    const fresh: SequencerIntent[] = [];
    plan.parked.forEach(({ intent }) => {
      if (this.park(intent, now)) fresh.push(intent);
    });
    const unparked: { intent: SequencerIntent; waitedMs: number }[] = [];
    // the wait is counted once and ends here; the deadline stays, should the intent come back to a park (it then
    // expires at once): a lane, or a lock retry, is not a park wait, the deadline must not force the intent there
    const leave = (intent: SequencerIntent) => {
      if (intent.parkedAt === undefined) return;
      unparked.push({ intent, waitedMs: now - intent.parkedAt });
      delete intent.parkedAt;
    };
    plan.deferred.forEach(({ intent, reason }) => {
      if (OWN_BOUND_WAITS.has(reason)) restartClock(intent);
      else leave(intent);
    });
    plan.order.forEach(({ leader, absorbed }) => [leader, ...absorbed].forEach(leave));
    return { fresh, unparked };
  }

  // A missing reference at apply (parkSoftRefs): the group parks again while its leader's clock runs, on that
  // clock (an absorbed intent shares the leader's application). False: expired, the failure path applies.
  parkAfterFailure(leader: SequencerIntent, absorbed: SequencerIntent[], now: number) {
    const deadline = leader.parkDeadline ?? now + this.deadlineMs;
    if (leader.expired || deadline <= now) return { parked: false, fresh: [] as SequencerIntent[] };
    const fresh: SequencerIntent[] = [];
    [leader, ...absorbed].forEach((intent) => {
      if (this.park(intent, now, deadline)) fresh.push(intent);
    });
    return { parked: true, fresh };
  }
}
