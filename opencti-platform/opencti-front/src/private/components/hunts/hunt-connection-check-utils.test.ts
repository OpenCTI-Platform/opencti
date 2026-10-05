import { describe, expect, it } from 'vitest';
import { CONNECTION_CHECK_STALE_MS, isStaleConnectionCheck } from './hunt-connection-check-utils';

const requestedAt = '2026-10-05T07:00:00.000Z';
const requestedMs = new Date(requestedAt).getTime();

describe('Connection test of a hunt connector', () => {
  it('should let a new test be asked for once a pending test is past the delay', () => {
    expect(isStaleConnectionCheck({ status: 'pending', requested_at: requestedAt }, requestedMs + CONNECTION_CHECK_STALE_MS + 1)).toBe(true);
  });

  it('should keep a recent pending test running', () => {
    expect(isStaleConnectionCheck({ status: 'pending', requested_at: requestedAt }, requestedMs + CONNECTION_CHECK_STALE_MS)).toBe(false);
  });

  it('should only apply to pending tests that carry their request date', () => {
    const later = requestedMs + 10 * CONNECTION_CHECK_STALE_MS;
    expect(isStaleConnectionCheck({ status: 'passed', requested_at: requestedAt }, later)).toBe(false);
    expect(isStaleConnectionCheck({ status: 'failed', requested_at: requestedAt }, later)).toBe(false);
    expect(isStaleConnectionCheck({ status: 'pending', requested_at: null }, later)).toBe(false);
    expect(isStaleConnectionCheck(null, later)).toBe(false);
  });
});
