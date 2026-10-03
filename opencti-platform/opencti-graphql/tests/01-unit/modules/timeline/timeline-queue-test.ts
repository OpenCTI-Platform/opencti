import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  claimDueTimelineRegenerations,
  clearTimelineRegenerationAttempts,
  retryDelayMs,
  retryTimelineRegeneration,
  TIMELINE_DEBOUNCE_MS,
  TIMELINE_MAX_RETRIES,
} from '../../../../src/modules/timeline/timeline-queue';

const attempts = new Map<string, number>();
const queue = new Map<string, number>();

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
    zrangebyscore: async (_key: string, _min: string, max: number) => [...queue.entries()].filter(([, due]) => due <= max).map(([id]) => id),
    zrem: async (_key: string, id: string) => (queue.delete(id) ? 1 : 0),
  }),
}));

describe('Timeline regeneration queue', () => {
  beforeEach(() => {
    attempts.clear();
    queue.clear();
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
});
