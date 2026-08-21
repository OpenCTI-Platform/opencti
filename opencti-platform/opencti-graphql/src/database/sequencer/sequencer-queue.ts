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
}
