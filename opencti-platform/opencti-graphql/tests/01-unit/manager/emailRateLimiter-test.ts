import { afterEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { createEmailRateLimiter, type EmailRateLimitRequest } from '../../../src/manager/publisherManager/emailRateLimiter';

const HOUR = 60 * 60 * 1000;
const START_OF_HOUR = Date.UTC(2026, 9, 30, 10, 0, 0);

const buildRequest = (userId: string, triggerKeys: string[]): EmailRateLimitRequest => ({
  nowInMs: START_OF_HOUR,
  userId,
  triggerKeys,
  isPerRecipientLimited: true,
});

describe('Email rate limiter', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should drop every email once the platform cap is used', () => {
    const limiter = createEmailRateLimiter({ maxPerHour: 2, maxPerTriggerRecipientPerHour: 0 });

    const allowed = ['a', 'b', 'c'].map((key) => limiter.filterAllowedTriggerKeys(buildRequest('user-u', [key])));

    expect(allowed).toEqual([['a'], ['b'], []]);
  });

  it('should never drop when both caps are 0', () => {
    const limiter = createEmailRateLimiter({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 0 });

    const allowed = Array.from({ length: 1000 }, () => limiter.filterAllowedTriggerKeys(buildRequest('user-u', ['a'])));

    expect(allowed.every((keys) => keys.length === 1)).toBe(true);
  });

  it('should count each trigger and recipient pair separately', () => {
    const limiter = createEmailRateLimiter({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 1 });

    const first = limiter.filterAllowedTriggerKeys(buildRequest('user-u', ['a', 'b']));
    const sameRecipient = limiter.filterAllowedTriggerKeys(buildRequest('user-u', ['a', 'c']));
    const otherRecipient = limiter.filterAllowedTriggerKeys(buildRequest('user-v', ['a']));

    expect(first).toEqual(['a', 'b']);
    expect(sameRecipient).toEqual(['c']);
    expect(otherRecipient).toEqual(['a']);
  });

  it('should skip the pair cap when not requested but still charge the platform cap', () => {
    const limiter = createEmailRateLimiter({ maxPerHour: 2, maxPerTriggerRecipientPerHour: 1 });
    const digestRequest = { ...buildRequest('user-u', ['digest']), isPerRecipientLimited: false };

    const allowed = [1, 2, 3].map(() => limiter.filterAllowedTriggerKeys(digestRequest));

    expect(allowed).toEqual([['digest'], ['digest'], []]);
  });

  it('should reset every counter at the next clock hour', () => {
    const limiter = createEmailRateLimiter({ maxPerHour: 1, maxPerTriggerRecipientPerHour: 1 });
    limiter.filterAllowedTriggerKeys(buildRequest('user-u', ['a']));

    const sameHour = limiter.filterAllowedTriggerKeys({ ...buildRequest('user-u', ['a']), nowInMs: START_OF_HOUR + HOUR - 1 });
    const nextHour = limiter.filterAllowedTriggerKeys({ ...buildRequest('user-u', ['a']), nowInMs: START_OF_HOUR + HOUR });

    expect(sameHour).toEqual([]);
    expect(nextHour).toEqual(['a']);
  });

  it('should warn once per trigger per hour and summarise the drops at the next hour', () => {
    const warnSpy = vi.spyOn(logApp, 'warn');
    const limiter = createEmailRateLimiter({ maxPerHour: 0, maxPerTriggerRecipientPerHour: 1 });
    ['user-u', 'user-v'].forEach((userId) => {
      limiter.filterAllowedTriggerKeys(buildRequest(userId, ['a']));
      limiter.filterAllowedTriggerKeys(buildRequest(userId, ['a']));
      limiter.filterAllowedTriggerKeys(buildRequest(userId, ['a']));
    });

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0][1]).toEqual({ triggerKey: 'a', maxPerTriggerRecipientPerHour: 1 });

    limiter.filterAllowedTriggerKeys({ ...buildRequest('user-u', ['a']), nowInMs: START_OF_HOUR + HOUR });

    expect(warnSpy).toHaveBeenCalledTimes(2);
    expect(warnSpy.mock.calls[1][1]).toEqual({ droppedAttempts: 4, distinctRecipients: 2, maxPerHour: 0, maxPerTriggerRecipientPerHour: 1 });
  });
});
