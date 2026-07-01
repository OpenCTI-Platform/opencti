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
