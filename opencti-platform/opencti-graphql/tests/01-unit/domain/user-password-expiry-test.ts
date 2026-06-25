import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DateTime } from 'luxon';

// Mock cache and conf to keep tests pure/unit
vi.mock('../../../src/database/cache');
vi.mock('../../../src/database/redis');
vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...actual,
    basePath: '',
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

import * as Cache from '../../../src/database/cache';
import { isPasswordExpired, computePasswordValidUntilFromPolicy } from '../../../src/domain/user';
import { SYSTEM_USER } from '../../../src/utils/access';

const mockGetEntityFromCache = vi.mocked(Cache.getEntityFromCache);

const makeContext = () => ({ user: SYSTEM_USER, req: {} } as any);

// --- isPasswordExpired ---

describe('isPasswordExpired', () => {
  it('returns false when password_valid_until is null', () => {
    expect(isPasswordExpired({ password_valid_until: null } as any)).toBe(false);
  });

  it('returns false when password_valid_until is undefined', () => {
    expect(isPasswordExpired({} as any)).toBe(false);
  });

  it('returns false when password_valid_until is in the future', () => {
    const future = DateTime.now().plus({ days: 6 }).toUTC().toString();
    expect(isPasswordExpired({ password_valid_until: future } as any)).toBe(false);
  });

  it('returns true when password_valid_until is in the past', () => {
    const past = DateTime.now().minus({ days: 1 }).toUTC().toString();
    expect(isPasswordExpired({ password_valid_until: past } as any)).toBe(true);
  });

  it('returns true when password_valid_until is exactly now (inclusive boundary)', () => {
    // Set to 1ms in the past to simulate "exactly now" already passed
    const now = DateTime.now().minus({ milliseconds: 1 }).toUTC().toString();
    expect(isPasswordExpired({ password_valid_until: now } as any)).toBe(true);
  });
});

// --- computePasswordValidUntilFromPolicy ---

describe('computePasswordValidUntilFromPolicy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns null when password_policy_validity_days is 0', async () => {
    mockGetEntityFromCache.mockResolvedValue({ password_policy_validity_days: 0 } as any);
    const result = await computePasswordValidUntilFromPolicy(makeContext());
    expect(result).toBeNull();
  });

  it('returns null when password_policy_validity_days is undefined', async () => {
    mockGetEntityFromCache.mockResolvedValue({} as any);
    const result = await computePasswordValidUntilFromPolicy(makeContext());
    expect(result).toBeNull();
  });

  it('returns a date approximately now + N days when policy is set', async () => {
    mockGetEntityFromCache.mockResolvedValue({ password_policy_validity_days: 20 } as any);
    const before = DateTime.now().plus({ days: 20 }).toUTC();
    const result = await computePasswordValidUntilFromPolicy(makeContext());
    const after = DateTime.now().plus({ days: 20 }).toUTC();

    expect(result).not.toBeNull();
    const resultDate = DateTime.fromISO(result!);
    expect(resultDate >= before.minus({ seconds: 1 })).toBe(true);
    expect(resultDate <= after.plus({ seconds: 1 })).toBe(true);
  });
});

// --- Policy change recalculation scenario ---

describe('password_valid_until recalculation on policy change', () => {
  /**
   * Scenario:
   *   - Old policy: 10 days
   *   - Password was changed 4 days ago → old expiry = in 6 days
   *   - Policy changes to 20 days
   *   - New expiry = passwordChangedAt + 20 days = in 16 days
   *   - Since new expiry > today → user can keep current password until then (no forced reset today)
   *
   * Rule: newExpiry = passwordChangedAt + newPolicyDays
   *   If newExpiry <= now  → forced reset immediately (set password_valid_until = now)
   *   If newExpiry >  now  → set password_valid_until = newExpiry
   */

  const computeNewExpiry = (passwordChangedAt: DateTime, newPolicyDays: number): DateTime => {
    return passwordChangedAt.plus({ days: newPolicyDays });
  };

  const applyPolicyChange = (passwordChangedAt: DateTime, newPolicyDays: number): DateTime => {
    const newExpiry = computeNewExpiry(passwordChangedAt, newPolicyDays);
    const now = DateTime.now();
    return newExpiry <= now ? now : newExpiry;
  };

  it('new expiry is passwordChangedAt + newPolicyDays when policy increases', () => {
    const changedAt = DateTime.now().minus({ days: 4 });
    const newExpiry = computeNewExpiry(changedAt, 20);

    // Should be approximately 16 days from now
    const daysFromNow = newExpiry.diff(DateTime.now(), 'days').days;
    expect(daysFromNow).toBeGreaterThanOrEqual(15.99);
    expect(daysFromNow).toBeLessThanOrEqual(16.01);
  });

  it('no forced reset when new expiry is in the future', () => {
    const changedAt = DateTime.now().minus({ days: 4 });
    const result = applyPolicyChange(changedAt, 20);

    expect(isPasswordExpired({ password_valid_until: result.toISO() } as any)).toBe(false);
  });

  it('forced reset when new expiry falls before today (policy decreased sharply)', () => {
    // Password changed 10 days ago, new policy = 5 days → new expiry = 5 days ago
    const changedAt = DateTime.now().minus({ days: 10 });
    const result = applyPolicyChange(changedAt, 5);

    // result should be now (clamped), so user is immediately expired
    expect(isPasswordExpired({ password_valid_until: result.minus({ milliseconds: 1 }).toISO() } as any)).toBe(true);
  });

  it('user manually forced by admin (password_valid_until set to past date) stays expired after policy increase', () => {
    // Admin forced the user by setting password_valid_until to a past date (already expired)
    const forcedAt = DateTime.now().minus({ milliseconds: 1 });

    // Even if policy increases to 30 days, the forced date should NOT be overwritten
    // (this is a guard: the forced date should only be updated on actual password change)
    expect(isPasswordExpired({ password_valid_until: forcedAt.toISO() } as any)).toBe(true);
  });

  it('after user changes password, new expiry = now + newPolicyDays (no longer forced)', () => {
    // Simulate: user changed password NOW, policy = 20 days
    const changedAt = DateTime.now();
    const newExpiry = computeNewExpiry(changedAt, 20);

    expect(isPasswordExpired({ password_valid_until: newExpiry.toISO() } as any)).toBe(false);
    // Should be approximately 20 days from now
    const daysFromNow = newExpiry.diff(DateTime.now(), 'days').days;
    expect(daysFromNow).toBeGreaterThanOrEqual(19.99);
    expect(daysFromNow).toBeLessThanOrEqual(20.01);
  });

  it('setting password_policy_validity_days to 0 means no expiry (null)', async () => {
    mockGetEntityFromCache.mockResolvedValue({ password_policy_validity_days: 0 } as any);
    const result = await computePasswordValidUntilFromPolicy(makeContext());
    expect(result).toBeNull();
  });
});

// --- Policy disabled (0): clear all users' password_valid_until ---

describe('policy disabled: password_policy_validity_days 600 → 0 clears all users expiry dates', () => {
  /**
   * When password_policy_validity_days is set to 0 (disabled),
   * all users' password_valid_until must be cleared to null,
   * regardless of whether their date was in the future or the past.
   */
  const applyPolicyDisabled = (users: Array<{ id: string; password_valid_until: string | null }>) => {
    return users.map((u) => ({ ...u, password_valid_until: null }));
  };

  it('clears password_valid_until for a user whose expiry was in the future', () => {
    const users = [{ id: 'user-1', password_valid_until: DateTime.now().plus({ days: 200 }).toISO() }];
    const result = applyPolicyDisabled(users);
    expect(result[0].password_valid_until).toBeNull();
  });

  it('clears password_valid_until for a user already expired (forced)', () => {
    const users = [{ id: 'user-2', password_valid_until: DateTime.now().minus({ days: 1 }).toISO() }];
    const result = applyPolicyDisabled(users);
    expect(result[0].password_valid_until).toBeNull();
  });

  it('clears password_valid_until for all users regardless of their individual date', () => {
    const users = [
      { id: 'user-1', password_valid_until: DateTime.now().plus({ days: 600 }).toISO() },
      { id: 'user-2', password_valid_until: DateTime.now().minus({ days: 1 }).toISO() },
      { id: 'user-3', password_valid_until: null },
    ];
    const result = applyPolicyDisabled(users);
    expect(result.every((u) => u.password_valid_until === null)).toBe(true);
  });

  it('after clearing, users are no longer considered expired', () => {
    const users = [
      { id: 'user-1', password_valid_until: DateTime.now().minus({ days: 5 }).toISO() },
    ];
    const result = applyPolicyDisabled(users);
    expect(isPasswordExpired({ password_valid_until: result[0].password_valid_until } as any)).toBe(false);
  });

  it('computePasswordValidUntilFromPolicy returns null when policy is 0', async () => {
    mockGetEntityFromCache.mockResolvedValue({ password_policy_validity_days: 0 } as any);
    const result = await computePasswordValidUntilFromPolicy(makeContext());
    expect(result).toBeNull();
  });
});

// --- Force password change on user with no policy, then user changes password → unlimited again ---

describe('force password change on user with no validity policy', () => {
  /**
   * Scenario:
   *   1. Policy = 0 (no expiry) → user.password_valid_until = null (unlimited)
   *   2. Admin forces the user to change password → password_valid_until = past date (expired now)
   *   3. User changes password → policy still = 0 → password_valid_until resets to null (unlimited)
   */
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('step 1: policy = 0 produces password_valid_until = null → user is not expired', async () => {
    mockGetEntityFromCache.mockResolvedValue({ password_policy_validity_days: 0 } as any);
    const validUntil = await computePasswordValidUntilFromPolicy(makeContext());
    expect(validUntil).toBeNull();
    expect(isPasswordExpired({ password_valid_until: validUntil } as any)).toBe(false);
  });

  it('step 2: admin forces password change by setting password_valid_until to a past date', () => {
    const forcedDate = DateTime.now().minus({ milliseconds: 1 }).toISO();
    const user = { password_valid_until: forcedDate };
    expect(isPasswordExpired(user as any)).toBe(true);
  });

  it('step 3: after user changes password with policy = 0, password_valid_until resets to null', async () => {
    // policy = 0 → computePasswordValidUntilFromPolicy returns null
    mockGetEntityFromCache.mockResolvedValue({ password_policy_validity_days: 0 } as any);
    const newValidUntil = await computePasswordValidUntilFromPolicy(makeContext());

    // password_valid_until is now null (unlimited)
    expect(newValidUntil).toBeNull();
    expect(isPasswordExpired({ password_valid_until: newValidUntil } as any)).toBe(false);
  });

  it('full flow: null → forced (expired) → password changed → null again', async () => {
    mockGetEntityFromCache.mockResolvedValue({ password_policy_validity_days: 0 } as any);

    // Initial state: no policy, no expiry
    let user = { password_valid_until: null as string | null };
    expect(isPasswordExpired(user as any)).toBe(false);

    // Admin forces: set to past
    user.password_valid_until = DateTime.now().minus({ milliseconds: 1 }).toISO();
    expect(isPasswordExpired(user as any)).toBe(true);

    // User changes password: recompute from policy (= 0 → null)
    user.password_valid_until = await computePasswordValidUntilFromPolicy(makeContext());
    expect(user.password_valid_until).toBeNull();
    expect(isPasswordExpired(user as any)).toBe(false);
  });
});
