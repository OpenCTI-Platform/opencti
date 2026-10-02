import { beforeEach, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';

vi.mock('../../../../src/database/redis');
vi.mock('../../../../src/database/engine', () => ({
  elRawUpdateByQuery: vi.fn(async () => ({ version_conflicts: 0 })),
  elRawCount: vi.fn(async () => 0),
}));
vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));
vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    isFeatureEnabled: vi.fn(() => true),
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

import { isFeatureEnabled, logApp } from '../../../../src/config/conf';
import { elRawCount, elRawUpdateByQuery } from '../../../../src/database/engine';
import { publishCacheResetEvent, redisConsumePasswordChangeAttempt } from '../../../../src/database/redis';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { SYSTEM_USER } from '../../../../src/utils/access';
import {
  checkPasswordNotReused,
  cleanUpPasswordHistoryWhenDisabled,
  clearAllUsersPasswordHistory,
  computeNextPasswordHistory,
  consumePasswordChangeAttempt,
  isLocalUser,
  isPasswordReused,
  isValidPasswordHistoryCount,
  readPasswordHistoryCount,
  trimAllUsersPasswordHistory,
} from '../../../../src/modules/user/user-password-history';

// Cost 4 keeps the suite fast; the code under test accepts any bcrypt cost
const hash = (password: string) => bcrypt.hashSync(password, 4);
const P1 = hash('First-password-1!');
const P2 = hash('Second-password-2!');
const P3 = hash('Third-password-3!');
const P4 = hash('Fourth-password-4!');

// The user is on P4, after P3, P2 and P1
const user = { id: 'user-1', password: P4, password_history: [P3, P2, P1] };
const context = { user: SYSTEM_USER, req: {} } as any;

describe('password history count', () => {
  beforeEach(() => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    vi.clearAllMocks();
  });

  it('accepts integers from 0 to 24 only', () => {
    [0, 1, 24].forEach((value) => expect(isValidPasswordHistoryCount(value)).toBe(true));
    [-1, 25, 2.5, '5', null, undefined].forEach((value) => expect(isValidPasswordHistoryCount(value)).toBe(false));
  });

  it('reads the stored value when the feature flag is on', () => {
    expect(readPasswordHistoryCount({ password_policy_history_count: 5 })).toBe(5);
    expect(readPasswordHistoryCount({})).toBe(0);
    expect(readPasswordHistoryCount(undefined)).toBe(0);
  });

  it('reads 0 when the feature flag is off, whatever is stored', () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    expect(readPasswordHistoryCount({ password_policy_history_count: 5 })).toBe(0);
  });

  it('reads an invalid stored value as 0 and logs a warning', () => {
    [-1, 25, 2.5].forEach((value) => expect(readPasswordHistoryCount({ password_policy_history_count: value })).toBe(0));
    expect(logApp.warn).toHaveBeenCalledTimes(3);
  });

  it('only applies to local users', () => {
    expect(isLocalUser({ external: false, user_service_account: false })).toBe(true);
    expect(isLocalUser({ external: true, user_service_account: false })).toBe(false);
    expect(isLocalUser({ external: false, user_service_account: true })).toBe(false);
  });
});

describe('computeNextPasswordHistory', () => {
  it('keeps nothing when N is 0 or 1', () => {
    expect(computeNextPasswordHistory(user, 0)).toEqual([]);
    expect(computeNextPasswordHistory(user, 1)).toEqual([]);
  });

  it('keeps the current hash and the newest stored ones, N - 1 in all', () => {
    expect(computeNextPasswordHistory(user, 2)).toEqual([P4]);
    expect(computeNextPasswordHistory(user, 3)).toEqual([P4, P3]);
    expect(computeNextPasswordHistory(user, 24)).toEqual([P4, P3, P2, P1]);
  });

  it('starts from the current hash when there is no history yet', () => {
    expect(computeNextPasswordHistory({ password: P4 }, 5)).toEqual([P4]);
  });

  it('drops values that are not bcrypt hashes', () => {
    const corrupted = { password: null as unknown as string, password_history: [P3, 'not-a-hash', 42 as unknown as string, P2] };
    expect(computeNextPasswordHistory(corrupted, 5)).toEqual([P3, P2]);
  });
});

describe('isPasswordReused', () => {
  it('refuses the current password and the oldest one still in the window', async () => {
    expect(await isPasswordReused(user, 'Fourth-password-4!', 3)).toBe(true);
    expect(await isPasswordReused(user, 'Second-password-2!', 3)).toBe(true);
  });

  it('accepts a password just outside the window, and a new one', async () => {
    expect(await isPasswordReused(user, 'First-password-1!', 3)).toBe(false);
    expect(await isPasswordReused(user, 'Brand-new-password-5!', 3)).toBe(false);
  });

  it('never refuses when N is 0', async () => {
    expect(await isPasswordReused(user, 'Fourth-password-4!', 0)).toBe(false);
  });

  it('compares exactly N hashes, wherever the match is', async () => {
    const compare = vi.spyOn(bcrypt, 'compare');
    for (const candidate of ['Fourth-password-4!', 'Second-password-2!', 'Brand-new-password-5!']) {
      compare.mockClear();
      await isPasswordReused(user, candidate, 3);
      expect(compare).toHaveBeenCalledTimes(3);
    }
    // Fewer stored hashes than N: the window is padded to the same amount of work
    compare.mockClear();
    await isPasswordReused({ password: P4 }, 'Brand-new-password-5!', 3);
    expect(compare).toHaveBeenCalledTimes(3);
    compare.mockRestore();
  });

  it('skips null and malformed hashes without throwing', async () => {
    const corrupted = { password: null as unknown as string, password_history: ['not-a-hash', P3] };
    expect(await isPasswordReused(corrupted, 'Third-password-3!', 3)).toBe(true);
  });

  it('matches on the first 72 bytes only, like login', async () => {
    const prefix = 'a'.repeat(71);
    const stored = { password: hash(`${prefix}b-first-ending`) };
    expect(await isPasswordReused(stored, `${prefix}b-other-ending`, 1)).toBe(true);
    expect(await isPasswordReused(stored, `${prefix}c-first-ending`, 1)).toBe(false);
  });
});

describe('checkPasswordNotReused', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('lets a new password through without any audit event', async () => {
    await expect(checkPasswordNotReused(context, { id: 'user-1' } as any, user, 'Brand-new-password-5!', 3)).resolves.toBeUndefined();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('refuses a reused password with PASSWORD_REUSED and records an unauthorized mutation without any secret', async () => {
    await expect(checkPasswordNotReused(context, { id: 'admin-1' } as any, user, 'Third-password-3!', 3))
      .rejects.toMatchObject({ extensions: { code: 'PASSWORD_REUSED' } });
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    const action = vi.mocked(publishUserAction).mock.calls[0][0] as any;
    expect(action).toMatchObject({
      event_type: 'mutation',
      event_scope: 'unauthorized',
      event_access: 'administration',
      status: 'error',
      context_data: { operation: 'password_reuse', input: { user_id: 'user-1', reason: 'PASSWORD_REUSED', flow: 'admin' } },
    });
    const serialized = JSON.stringify(action.context_data);
    expect(serialized).not.toContain('Third-password-3!');
    expect(serialized).not.toContain(P3);
    expect(logApp.warn).toHaveBeenCalledWith('[PASSWORD_HISTORY] Password reuse refused', { target_user_id: 'user-1', submitter_id: 'admin-1', flow: 'admin' });
  });

  it('names the flow from who submitted the password', async () => {
    const flowOf = async (submitter: any) => {
      vi.mocked(publishUserAction).mockClear();
      await checkPasswordNotReused(context, submitter, user, 'Fourth-password-4!', 3).catch(() => undefined);
      return (vi.mocked(publishUserAction).mock.calls[0][0] as any).context_data.input.flow;
    };
    expect(await flowOf({ id: 'user-1' })).toBe('self');
    expect(await flowOf(SYSTEM_USER)).toBe('reset');
  });
});

describe('consumePasswordChangeAttempt', () => {
  it('lets an attempt through within the limit', async () => {
    vi.mocked(redisConsumePasswordChangeAttempt).mockResolvedValue(true);
    await expect(consumePasswordChangeAttempt('user-1')).resolves.toBeUndefined();
  });

  it('refuses an attempt over the limit with PASSWORD_CHANGE_THROTTLED', async () => {
    vi.mocked(redisConsumePasswordChangeAttempt).mockResolvedValue(false);
    await expect(consumePasswordChangeAttempt('user-1')).rejects.toMatchObject({ extensions: { code: 'PASSWORD_CHANGE_THROTTLED' } });
  });
});

describe('bulk clean-up of password histories', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(elRawUpdateByQuery).mockResolvedValue({ version_conflicts: 0 });
    vi.mocked(elRawCount).mockResolvedValue(0);
  });

  it('removes every history, external users included, and resets the user cache', async () => {
    await clearAllUsersPasswordHistory();
    const query = vi.mocked(elRawUpdateByQuery).mock.calls[0][0];
    expect(query.body.script.source).toContain("remove('password_history')");
    expect(JSON.stringify(query.body.query)).not.toContain('external');
    expect(publishCacheResetEvent).toHaveBeenCalledWith('User');
  });

  it('retries while documents were skipped for a version conflict', async () => {
    vi.mocked(elRawUpdateByQuery).mockResolvedValueOnce({ version_conflicts: 2 }).mockResolvedValueOnce({ version_conflicts: 0 });
    await clearAllUsersPasswordHistory();
    expect(elRawUpdateByQuery).toHaveBeenCalledTimes(2);
  });

  it('warns when histories remain after the clean-up', async () => {
    vi.mocked(elRawCount).mockResolvedValue(3);
    await clearAllUsersPasswordHistory();
    expect(logApp.warn).toHaveBeenCalledWith('[PASSWORD_HISTORY] Some users still hold a password history after the clean-up', { remaining: 3 });
  });

  it('trims to N - 1 hashes, and clears everything for N of 0 or 1', async () => {
    await trimAllUsersPasswordHistory(5);
    expect(vi.mocked(elRawUpdateByQuery).mock.calls[0][0].body.script.params).toEqual({ keep: 4 });
    vi.mocked(elRawUpdateByQuery).mockClear();
    await trimAllUsersPasswordHistory(1);
    expect(vi.mocked(elRawUpdateByQuery).mock.calls[0][0].body.script.source).toContain("remove('password_history')");
  });
});

describe('cleanUpPasswordHistoryWhenDisabled', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(elRawUpdateByQuery).mockResolvedValue({ version_conflicts: 0 });
  });

  it('does nothing while the feature flag is on', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    const reset = vi.fn();
    await cleanUpPasswordHistoryWhenDisabled({ password_policy_history_count: 5 }, reset);
    expect(reset).not.toHaveBeenCalled();
    expect(elRawUpdateByQuery).not.toHaveBeenCalled();
  });

  it('does nothing when the flag is off and nothing is stored', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    vi.mocked(elRawCount).mockResolvedValue(0);
    const reset = vi.fn();
    await cleanUpPasswordHistoryWhenDisabled({ password_policy_history_count: 0 }, reset);
    expect(reset).not.toHaveBeenCalled();
    expect(elRawUpdateByQuery).not.toHaveBeenCalled();
  });

  it('resets the stored value and deletes every history when the flag is off', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    vi.mocked(elRawCount).mockResolvedValueOnce(3).mockResolvedValue(0);
    const reset = vi.fn(async () => undefined);
    await cleanUpPasswordHistoryWhenDisabled({ password_policy_history_count: 5 }, reset);
    expect(reset).toHaveBeenCalledTimes(1);
    expect(vi.mocked(elRawUpdateByQuery).mock.calls[0][0].body.script.source).toContain("remove('password_history')");
  });
});
