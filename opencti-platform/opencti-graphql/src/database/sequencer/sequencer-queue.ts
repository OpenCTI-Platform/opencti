// POC ingestion sequencer (plan 0009, Stage B4). Bounded intent queue: caps by count and bytes
// (knobs); when full, submit awaits a slot, so backpressure flows through the existing admission
// control (the HTTP request waits, the worker thread waits, no new protocol). Dequeue is
// round-robin by source (applicant_id) so one flooding connector cannot starve the others.
import { SEQUENCER_CONFIG } from './sequencer-config';
import { sequencerMetrics } from './sequencer-metrics';
import type { SequencerIntent } from './sequencer-intent';

export class SequencerQueue {
  private bySource = new Map<string, SequencerIntent[]>();

  private ring: string[] = [];

  private ringIndex = 0;

  private count = 0;

  private bytes = 0;

  // FIFO of submitters waiting for a free slot (queue full)
  private slotWaiters: Array<() => void> = [];

  // FIFO of takers waiting for an intent (queue empty); the loop is the only taker today
  private takeWaiters: Array<(intent: SequencerIntent) => void> = [];

  size() {
    return this.count;
  }

  private hasCapacity(intent: SequencerIntent) {
    if (this.count >= SEQUENCER_CONFIG.queueMaxIntents) return false;
    if (this.count > 0 && this.bytes + intent.sizeBytes > SEQUENCER_CONFIG.queueMaxBytes) return false;
    return true;
  }

  private push(intent: SequencerIntent) {
    const queue = this.bySource.get(intent.source);
    if (queue) {
      queue.push(intent);
    } else {
      this.bySource.set(intent.source, [intent]);
      this.ring.push(intent.source);
    }
    this.count += 1;
    this.bytes += intent.sizeBytes;
    sequencerMetrics.queueDepth(this.count);
  }

  private pop(): SequencerIntent | undefined {
    if (this.count === 0) return undefined;
    for (let i = 0; i < this.ring.length; i += 1) {
      const idx = (this.ringIndex + i) % this.ring.length;
      const source = this.ring[idx];
      const queue = this.bySource.get(source);
      if (queue && queue.length > 0) {
        const intent = queue.shift() as SequencerIntent;
        if (queue.length === 0) {
          this.bySource.delete(source);
          this.ring.splice(idx, 1);
          this.ringIndex = this.ring.length === 0 ? 0 : idx % this.ring.length;
        } else {
          this.ringIndex = (idx + 1) % this.ring.length;
        }
        this.count -= 1;
        this.bytes -= intent.sizeBytes;
        sequencerMetrics.queueDepth(this.count);
        const waiter = this.slotWaiters.shift();
        if (waiter) waiter();
        return intent;
      }
    }
    return undefined;
  }

  // Awaits a slot if the queue is full, then enqueues. Hands the intent straight to a waiting
  // taker when the queue is empty (no extra tick).
  async put(intent: SequencerIntent): Promise<void> {
    while (!this.hasCapacity(intent)) {
      await new Promise<void>((resolve) => this.slotWaiters.push(resolve));
    }
    const taker = this.takeWaiters.shift();
    if (taker && this.count === 0) {
      taker(intent);
      return;
    }
    this.push(intent);
  }

  // Awaits until an intent is available (the pass-through loop's only wait point).
  async take(): Promise<SequencerIntent> {
    const intent = this.pop();
    if (intent) return intent;
    return new Promise<SequencerIntent>((resolve) => this.takeWaiters.push(resolve));
  }

  // Non-blocking dequeue (batch assembly of already-queued intents).
  tryPop(): SequencerIntent | undefined {
    return this.pop();
  }

  // Awaits an intent for at most timeoutMs; null on timeout. Used when parked intents exist:
  // the loop must wake at the nearest parking deadline even if nothing new arrives.
  async takeWithTimeout(timeoutMs: number): Promise<SequencerIntent | null> {
    const intent = this.pop();
    if (intent) return intent;
    return new Promise<SequencerIntent | null>((resolve) => {
      let settled = false;
      const waiter = (taken: SequencerIntent) => {
        if (settled) {
          // timed out before an intent arrived: put it back for the next taker
          this.push(taken);
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve(taken);
      };
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        const idx = this.takeWaiters.indexOf(waiter);
        if (idx >= 0) this.takeWaiters.splice(idx, 1);
        resolve(null);
      }, Math.max(1, timeoutMs));
      this.takeWaiters.push(waiter);
    });
  }

  // Batch formation (plan 0009 §2.6, C1): the loop takes EVERYTHING queued when it becomes
  // free (round-robin per source through pop), bounded by the size/bytes caps. No fixed
  // timer: the gathering window IS the previous batch's commit. gather_window_ms (default 0)
  // optionally waits once after the first intent, for mid-load batching.
  async takeBatch(maxCount: number, maxBytes: number, gatherWindowMs: number): Promise<SequencerIntent[]> {
    const first = await this.take();
    if (gatherWindowMs > 0) {
      await new Promise<void>((resolve) => {
        setTimeout(resolve, gatherWindowMs);
      });
    }
    const batch: SequencerIntent[] = [first];
    let bytes = first.sizeBytes;
    while (batch.length < maxCount) {
      const next = this.pop();
      if (!next) break;
      if (bytes + next.sizeBytes > maxBytes) {
        // over the byte cap: put it back at the front of its source lane for the next batch
        const lane = this.bySource.get(next.source);
        if (lane) {
          lane.unshift(next);
        } else {
          this.bySource.set(next.source, [next]);
          this.ring.push(next.source);
        }
        this.count += 1;
        this.bytes += next.sizeBytes;
        break;
      }
      batch.push(next);
      bytes += next.sizeBytes;
    }
    return batch;
  }
}
