// POC ingestion sequencer: deferred lanes with event-driven wake-up (B10, 2026-09-16).
//
// Until now the loop re-admitted ONE deferred intent per target lane at the start of every
// cycle, up to the batch cap, and drained the queue afterwards. A deferral whose producer sits
// in the queue ("queued_producer") therefore consumed a batch slot every cycle while waiting
// for a queue drain that never came once the lanes alone filled the cap: the first full-mix
// run of the chunk path livelocked (0 obj/s, 104 empty cycles/s, ~20,900 deferrals/s, queue
// depth flat). The large bundles of that corpus defer hundreds of consumers on a few queued
// producers; mix140k never reached the cap, which hid the flaw.
//
// This module keeps the per-target FIFO lanes but makes a deferral WAIT for the ids it
// depends on: it is re-admitted only when those ids land (or fail) in a later batch, or when
// its wait TTL expires (a missed wake must never become an infinite wait). Re-admissions per
// cycle are capped so the queue always keeps room. Lane residents are indexed like queued
// intents: a producer that is itself deferred still counts as "certain, pending".
import { SEQUENCER_CONFIG } from './sequencer-config';
import { sequencerMetrics } from './sequencer-metrics';
import type { SequencerIntent } from './sequencer-intent';

export interface LaneEntry {
  intent: SequencerIntent;
  laneKey: string;
  waitingOn: Set<string>;
  deadline: number;
  expiries: number;
}

export interface LaneAdmission {
  intents: SequencerIntent[];
  // waiters whose TTL expired deferred_wait_max_expiries times: the loop applies them as-is
  // (forceDirect), today's path decides (apply, reject, retain)
  exhausted: SequencerIntent[];
  skipped: number;
}

export class DeferredLanes {
  private lanes = new Map<string, LaneEntry[]>();

  private waitersById = new Map<string, Set<LaneEntry>>();

  private residents = new Map<string, number>();

  private count = 0;

  private bytes = 0;

  private waiting = 0;

  size() {
    return this.count;
  }

  sizeBytes() {
    return this.bytes;
  }

  laneCount() {
    return this.lanes.size;
  }

  waitingCount() {
    return this.waiting;
  }

  // a producer parked in a lane is as certain as one in the queue (chains of deferrals)
  hasResident(id: string): boolean {
    return this.residents.has(id);
  }

  defer(laneKey: string, intent: SequencerIntent, waitingOn: string[] = []) {
    const ids = waitingOn.filter((id) => typeof id === 'string' && id.length > 0);
    const entry: LaneEntry = {
      intent,
      laneKey,
      waitingOn: new Set(ids),
      deadline: Date.now() + SEQUENCER_CONFIG.deferredWaitTtlMs,
      expiries: intent.deferredWaitExpiries ?? 0,
    };
    const lane = this.lanes.get(laneKey);
    if (lane) lane.push(entry); else this.lanes.set(laneKey, [entry]);
    this.count += 1;
    this.bytes += intent.sizeBytes;
    intent.candidateIds.forEach((id) => this.residents.set(id, (this.residents.get(id) ?? 0) + 1));
    if (entry.waitingOn.size > 0) {
      this.waiting += 1;
      entry.waitingOn.forEach((id) => {
        const set = this.waitersById.get(id);
        if (set) set.add(entry); else this.waitersById.set(id, new Set([entry]));
      });
      sequencerMetrics.laneEvent('registered');
    }
    this.gauges();
  }

  // ids of a batch that settled (landed after commit, or failed): their waiters become ready
  wake(ids: string[], cause: 'landed' | 'failed') {
    let woken = 0;
    ids.forEach((id) => {
      const set = this.waitersById.get(id);
      if (!set) return;
      this.waitersById.delete(id);
      set.forEach((entry) => {
        if (entry.waitingOn.size === 0) return;
        this.unregister(entry);
        woken += 1;
      });
    });
    if (woken > 0) {
      sequencerMetrics.laneEvent(cause === 'landed' ? 'woken_landed' : 'woken_failed', woken);
      this.gauges();
    }
  }

  // one ready head per lane, at most `max`: a head still waiting is skipped without a slot
  // unless its TTL expired (re-admitted anyway, and declared exhausted at the limit)
  admit(max: number, now = Date.now()): LaneAdmission {
    const intents: SequencerIntent[] = [];
    const exhausted: SequencerIntent[] = [];
    let skipped = 0;
    for (const [laneKey, lane] of this.lanes) {
      if (intents.length >= max) break;
      const head = lane[0];
      if (!head) {
        this.lanes.delete(laneKey);
        continue;
      }
      if (head.waitingOn.size > 0) {
        if (now < head.deadline) {
          skipped += 1;
          continue;
        }
        this.unregister(head);
        head.expiries += 1;
        head.intent.deferredWaitExpiries = head.expiries; // carried across re-deferrals
        sequencerMetrics.laneEvent('expired');
        if (head.expiries >= SEQUENCER_CONFIG.deferredWaitMaxExpiries) {
          sequencerMetrics.laneEvent('exhausted');
          exhausted.push(head.intent);
        }
      }
      lane.shift();
      if (lane.length === 0) this.lanes.delete(laneKey);
      this.count -= 1;
      this.bytes -= head.intent.sizeBytes;
      head.intent.candidateIds.forEach((id) => {
        const current = this.residents.get(id);
        if (current === undefined) return;
        if (current <= 1) this.residents.delete(id); else this.residents.set(id, current - 1);
      });
      intents.push(head.intent);
    }
    if (intents.length > 0) sequencerMetrics.laneEvent('readmitted', intents.length);
    if (skipped > 0) sequencerMetrics.laneEvent('skipped', skipped);
    this.gauges();
    return { intents, exhausted, skipped };
  }

  private unregister(entry: LaneEntry) {
    entry.waitingOn.forEach((id) => {
      const set = this.waitersById.get(id);
      if (!set) return;
      set.delete(entry);
      if (set.size === 0) this.waitersById.delete(id);
    });
    entry.waitingOn.clear();
    this.waiting -= 1;
  }

  private gauges() {
    sequencerMetrics.lanes(this.lanes.size, this.waiting);
  }
}
