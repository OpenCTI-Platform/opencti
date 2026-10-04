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
    zrem: async (_key: string, id: string) => (inFlight.delete(id) ? 1 : 0),
    // The claim script: expired leases back to the queue (NX), then the due members not in flight, at most `limit`,
    // moved in flight
    eval: async (_script: string, _numKeys: number, _queueKey: string, _inFlightKey: string, max: number, limit: number, leaseEnd: number) => {
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
      expect(await claimDueTimelineRegenerations(10)).toEqual(retryDelayMs(attempt) === 0 ? ['case-1'] : []);
      // Like the manager: the claim of the failed attempt is acknowledged once its retry is scheduled
      await acknowledgeTimelineRegeneration('case-1');
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
    expect(await claimDueTimelineRegenerations(10)).toEqual(['case-3']);
    expect(queue.has('case-3')).toBe(false);
    expect(inFlight.get('case-3')).toBeGreaterThanOrEqual(Date.now());
    // Claimed once: a second claim within the lease does not hand it out again
    expect(await claimDueTimelineRegenerations(10)).toEqual([]);
    await acknowledgeTimelineRegeneration('case-3');
    expect(inFlight.has('case-3')).toBe(false);
  });

  it('should keep a container scheduled again during its regeneration queued until the running claim is acknowledged', async () => {
    await enqueueTimelineRegeneration(['case-5'], 0);
    expect(await claimDueTimelineRegenerations(10)).toEqual(['case-5']);
    const lease = inFlight.get('case-5');
    // A change while the regeneration runs: the new schedule waits, the running lease is left untouched
    await enqueueTimelineRegeneration(['case-5'], 0);
    expect(await claimDueTimelineRegenerations(10)).toEqual([]);
    expect(queue.has('case-5')).toBe(true);
    expect(inFlight.get('case-5')).toEqual(lease);
    await acknowledgeTimelineRegeneration('case-5');
    expect(await claimDueTimelineRegenerations(10)).toEqual(['case-5']);
  });

  it('should hand out again a claim whose lease expired before it was acknowledged', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-04T10:00:00.000Z'));
    await enqueueTimelineRegeneration(['case-4'], 0);
    expect(await claimDueTimelineRegenerations(10)).toEqual(['case-4']);
    // The manager stopped before handling it: once the lease is over, the container is due again
    vi.setSystemTime(new Date(Date.now() + TIMELINE_CLAIM_LEASE_MS));
    expect(await claimDueTimelineRegenerations(10)).toEqual(['case-4']);
    expect(inFlight.get('case-4')).toEqual(Date.now() + TIMELINE_CLAIM_LEASE_MS);
  });
});
