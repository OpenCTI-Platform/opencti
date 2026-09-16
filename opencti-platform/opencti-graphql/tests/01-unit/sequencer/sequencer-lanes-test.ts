import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DeferredLanes } from '../../../src/database/sequencer/sequencer-lanes';
import { buildIntent } from '../../../src/database/sequencer/sequencer-intent';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const intentWith = (name: string, candidateIds: string[]) => buildIntent({
  kind: 'relation',
  type: 'uses',
  input: { name },
  user: { id: 'u', origin: { applicant_id: 's' } } as unknown as AuthUser,
  context: {} as unknown as AuthContext,
  opts: {},
  candidateIds,
  apply: async () => name,
});

const savedTtl = SEQUENCER_CONFIG.deferredWaitTtlMs;
const savedExpiries = SEQUENCER_CONFIG.deferredWaitMaxExpiries;

describe('sequencer deferred lanes with wake-up (B10)', () => {
  beforeAll(() => {
    SEQUENCER_CONFIG.deferredWaitTtlMs = 1000;
    SEQUENCER_CONFIG.deferredWaitMaxExpiries = 2;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.deferredWaitTtlMs = savedTtl;
    SEQUENCER_CONFIG.deferredWaitMaxExpiries = savedExpiries;
  });

  it('re-admits a deferral without waiting ids on the next admission, one per lane, capped', () => {
    const lanes = new DeferredLanes();
    for (let i = 0; i < 5; i += 1) lanes.defer(`lane-${i}`, intentWith(`r${i}`, [`relationship--${i}`]));
    lanes.defer('lane-0', intentWith('r0-second', ['relationship--0b']));
    expect(lanes.size()).toBe(6);
    expect(lanes.laneCount()).toBe(5);
    const first = lanes.admit(3);
    expect(first.intents.map((i) => i.input.name)).toEqual(['r0', 'r1', 'r2']);
    expect(first.skipped).toBe(0);
    // lane-0 kept its insertion position (not emptied), so its second entry comes first
    const second = lanes.admit(10);
    expect(second.intents.map((i) => i.input.name)).toEqual(['r0-second', 'r3', 'r4']);
    expect(lanes.size()).toBe(0);
    expect(lanes.laneCount()).toBe(0);
  });

  it('a deferral waiting on a producer takes no slot until the producer lands', () => {
    const lanes = new DeferredLanes();
    const waiter = intentWith('consumer', ['relationship--c']);
    lanes.defer('lane-c', waiter, ['malware--producer']);
    lanes.defer('lane-x', intentWith('ready', ['relationship--x']));
    expect(lanes.waitingCount()).toBe(1);
    const before = lanes.admit(10);
    expect(before.intents.map((i) => i.input.name)).toEqual(['ready']);
    expect(before.skipped).toBe(1);
    lanes.wake(['malware--producer'], 'landed');
    expect(lanes.waitingCount()).toBe(0);
    const after = lanes.admit(10);
    expect(after.intents).toEqual([waiter]);
    expect(after.exhausted).toEqual([]);
  });

  it('a failed producer wakes its waiters too, and a waiter on several ids is released once', () => {
    const lanes = new DeferredLanes();
    const waiter = intentWith('consumer', ['relationship--c']);
    lanes.defer('lane-c', waiter, ['malware--from', 'attack-pattern--to']);
    lanes.wake(['malware--from'], 'failed');
    expect(lanes.waitingCount()).toBe(0);
    lanes.wake(['attack-pattern--to'], 'landed'); // no double release
    expect(lanes.admit(10).intents).toEqual([waiter]);
  });

  it('lane residents count as pending producers', () => {
    const lanes = new DeferredLanes();
    lanes.defer('lane-p', intentWith('producer', ['malware--p', 'malware--p-stix']), ['identity--author']);
    expect(lanes.hasResident('malware--p')).toBe(true);
    expect(lanes.hasResident('malware--p-stix')).toBe(true);
    lanes.wake(['identity--author'], 'landed');
    lanes.admit(10);
    expect(lanes.hasResident('malware--p')).toBe(false);
  });

  it('an expired wait is re-admitted anyway and declared exhausted at the limit', () => {
    const lanes = new DeferredLanes();
    const waiter = intentWith('stuck', ['relationship--s']);
    lanes.defer('lane-s', waiter, ['malware--never']);
    const now = Date.now();
    expect(lanes.admit(10, now).skipped).toBe(1);
    const expired = lanes.admit(10, now + SEQUENCER_CONFIG.deferredWaitTtlMs + 1);
    expect(expired.intents).toEqual([waiter]);
    expect(expired.exhausted).toEqual([]); // first expiry: re-plan
    // the loop re-defers the same intent: the expiry count is carried by the intent
    lanes.defer('lane-s', waiter, ['malware--never']);
    const secondExpiry = lanes.admit(10, now + 2 * SEQUENCER_CONFIG.deferredWaitTtlMs + 2);
    expect(secondExpiry.intents).toEqual([waiter]);
    expect(secondExpiry.exhausted).toEqual([waiter]); // limit 2 reached: applies as-is
    expect(waiter.deferredWaitExpiries).toBe(2);
  });

  it('never starves: with more waiting lanes than the cap, admission returns nothing and reports the skips', () => {
    const lanes = new DeferredLanes();
    for (let i = 0; i < 300; i += 1) lanes.defer(`lane-${i}`, intentWith(`r${i}`, [`relationship--${i}`]), ['malware--late']);
    const admission = lanes.admit(100);
    expect(admission.intents).toEqual([]);
    expect(admission.skipped).toBe(300);
    lanes.wake(['malware--late'], 'landed');
    expect(lanes.admit(100).intents.length).toBe(100);
    expect(lanes.admit(100).intents.length).toBe(100);
    expect(lanes.admit(100).intents.length).toBe(100);
    expect(lanes.size()).toBe(0);
  });
});
