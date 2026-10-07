import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  acknowledgeTimelineRegeneration,
  claimDueTimelineRegenerations,
  clearTimelineRegenerationAttempts,
  enqueueTimelineRegeneration,
  retryDelayMs,
  retryTimelineRegeneration,
  TIMELINE_CLAIM_LEASE_MS,
  TIMELINE_DEBOUNCE_MS,
  TIMELINE_MAX_RETRIES,
} from '../../../../src/modules/timeline/timeline-queue';

const attempts = new Map<string, number>();
const queue = new Map<string, number>();
const inFlight = new Map<string, number>();

vi.mock('../../../../src/database/redis', () => ({
  getClientBase: () => ({
    hincrby: async (_key: string, field: string, increment: number) => {
      const value = (attempts.get(field) ?? 0) + increment;
      attempts.set(field, value);
      return value;
    },
    hdel: async (_key: string, field: string) => (attempts.delete(field) ? 1 : 0),
    zadd: async (_key: string, _mode: string, ...args: Array<number | string>) => {
      for (let index = 0; index < args.length; index += 2) {
        const id = args[index + 1] as string;
        if (!queue.has(id)) queue.set(id, args[index] as number);
      }
      return 1;
    },
    eval: async (_script: string, numKeys: number, ...args: Array<string | number>) => {
      // The acknowledge script: the claim is released only while its lease is the one in flight
      if (numKeys === 1) {
        const [, id, lease] = args as [string, string, number];
        if (inFlight.get(id) !== Number(lease)) return 0;
        inFlight.delete(id);
        return 1;
      }
      // The claim script: expired leases back to the queue (NX), then the due members not in flight, at most `limit`,
      // moved in flight
      const [, , max, limit, leaseEnd] = args as [string, string, number, number, number];
      [...inFlight.entries()].filter(([, end]) => end <= max).forEach(([id]) => {
        inFlight.delete(id);
        if (!queue.has(id)) queue.set(id, max);
      });
      const due = [...queue.entries()].filter(([id, score]) => score <= max && !inFlight.has(id))
        .sort((a, b) => a[1] - b[1]).slice(0, limit).map(([id]) => id);
      due.forEach((id) => {
        queue.delete(id);
        inFlight.set(id, leaseEnd);
      });
      return due;
    },
  }),
}));

describe('Timeline regeneration queue', () => {
  beforeEach(() => {
    attempts.clear();
    queue.clear();
    inFlight.clear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should double the retry delay at each attempt', () => {
    expect(retryDelayMs(1)).toEqual(TIMELINE_DEBOUNCE_MS * 2);
    expect(retryDelayMs(2)).toEqual(TIMELINE_DEBOUNCE_MS * 4);
    expect(retryDelayMs(3)).toEqual(TIMELINE_DEBOUNCE_MS * 8);
  });

  it('should schedule a failed regeneration again until the retries are exhausted', async () => {
    const before = Date.now();
    for (let attempt = 1; attempt <= TIMELINE_MAX_RETRIES; attempt += 1) {
      expect(await retryTimelineRegeneration('case-1')).toBe(true);
      const due = queue.get('case-1') as number;
      expect(due).toBeGreaterThanOrEqual(before + retryDelayMs(attempt));
      const claimed = await claimDueTimelineRegenerations(10);
      expect(claimed.containerIds).toEqual(retryDelayMs(attempt) === 0 ? ['case-1'] : []);
      // Like the manager: the claim of the failed attempt is acknowledged once its retry is scheduled
      await acknowledgeTimelineRegeneration('case-1', claimed.lease);
      queue.delete('case-1');
    }
    expect(await retryTimelineRegeneration('case-1')).toBe(false);
    expect(queue.has('case-1')).toBe(false);
    expect(attempts.has('case-1')).toBe(false);
  });

  it('should start counting again after a successful regeneration', async () => {
    await retryTimelineRegeneration('case-2');
    await retryTimelineRegeneration('case-2');
    await clearTimelineRegenerationAttempts('case-2');
    queue.clear();
    expect(await retryTimelineRegeneration('case-2')).toBe(true);
    expect(attempts.get('case-2')).toEqual(1);
  });

  it('should keep a claim in flight until it is acknowledged', async () => {
    await enqueueTimelineRegeneration(['case-3'], 0);
    const claimed = await claimDueTimelineRegenerations(10);
    expect(claimed.containerIds).toEqual(['case-3']);
    expect(queue.has('case-3')).toBe(false);
    expect(inFlight.get('case-3')).toEqual(claimed.lease);
    // Claimed once: a second claim within the lease does not hand it out again
    expect((await claimDueTimelineRegenerations(10)).containerIds).toEqual([]);
    expect(await acknowledgeTimelineRegeneration('case-3', claimed.lease)).toBe(true);
    expect(inFlight.has('case-3')).toBe(false);
  });

  it('should keep a container scheduled again during its regeneration queued until the running claim is acknowledged', async () => {
    await enqueueTimelineRegeneration(['case-5'], 0);
    const claimed = await claimDueTimelineRegenerations(10);
    expect(claimed.containerIds).toEqual(['case-5']);
    // A change while the regeneration runs: the new schedule waits, the running lease is left untouched
    await enqueueTimelineRegeneration(['case-5'], 0);
    expect((await claimDueTimelineRegenerations(10)).containerIds).toEqual([]);
    expect(queue.has('case-5')).toBe(true);
    expect(inFlight.get('case-5')).toEqual(claimed.lease);
    await acknowledgeTimelineRegeneration('case-5', claimed.lease);
    expect((await claimDueTimelineRegenerations(10)).containerIds).toEqual(['case-5']);
  });

  it('should hand out again a claim whose lease expired before it was acknowledged', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-04T10:00:00.000Z'));
    await enqueueTimelineRegeneration(['case-4'], 0);
    expect((await claimDueTimelineRegenerations(10)).containerIds).toEqual(['case-4']);
    // The manager stopped before handling it: once the lease is over, the container is due again
    vi.setSystemTime(new Date(Date.now() + TIMELINE_CLAIM_LEASE_MS));
    const reclaimed = await claimDueTimelineRegenerations(10);
    expect(reclaimed.containerIds).toEqual(['case-4']);
    expect(inFlight.get('case-4')).toEqual(Date.now() + TIMELINE_CLAIM_LEASE_MS);
    expect(reclaimed.lease).toEqual(Date.now() + TIMELINE_CLAIM_LEASE_MS);
  });

  it('should never let a worker that outlived its lease release the later claim of the container', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-04T10:00:00.000Z'));
    await enqueueTimelineRegeneration(['case-6'], 0);
    const first = await claimDueTimelineRegenerations(10);
    vi.setSystemTime(new Date(Date.now() + TIMELINE_CLAIM_LEASE_MS));
    const second = await claimDueTimelineRegenerations(10);
    expect(second.containerIds).toEqual(['case-6']);
    // The first worker finishes late: the claim of the second one stays in flight, protected by its lease
    expect(await acknowledgeTimelineRegeneration('case-6', first.lease)).toBe(false);
    expect(inFlight.get('case-6')).toEqual(second.lease);
    expect(await acknowledgeTimelineRegeneration('case-6', second.lease)).toBe(true);
    expect(inFlight.has('case-6')).toBe(false);
  });
});
