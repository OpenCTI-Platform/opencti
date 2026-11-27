import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/engine', () => ({
  elRawSearch: vi.fn(async () => ({ hits: { hits: [] } })),
}));
vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));
vi.mock('../../../../src/enterprise-edition/ee', () => ({
  isEnterpriseEditionFromSettings: vi.fn(() => true),
}));
vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

import { logApp } from '../../../../src/config/conf';
import { getEntityFromCache } from '../../../../src/database/cache';
import { elRawSearch } from '../../../../src/database/engine';
import { isEnterpriseEditionFromSettings } from '../../../../src/enterprise-edition/ee';
import {
  checkLoginHistoryCountEdit,
  findUserLoginHistory,
  isValidLoginHistoryCount,
  LOGIN_HISTORY_MAX_COUNT,
  readLoginHistoryCount,
} from '../../../../src/modules/user/user-login-history';
import { SYSTEM_USER } from '../../../../src/utils/access';

const context = { user: SYSTEM_USER, req: {} } as any;
const user = { id: 'user-1' } as any;

describe('login history count', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('accepts integers from 0 to the maximum only', () => {
    [0, 1, LOGIN_HISTORY_MAX_COUNT].forEach((value) => expect(isValidLoginHistoryCount(value)).toBe(true));
    [-1, LOGIN_HISTORY_MAX_COUNT + 1, 2.5, '5', null, undefined].forEach((value) => expect(isValidLoginHistoryCount(value)).toBe(false));
  });

  it('reads the stored value, and 0 when none is stored', () => {
    expect(readLoginHistoryCount({ platform_login_history_count: 5 })).toBe(5);
    expect(readLoginHistoryCount({})).toBe(0);
    expect(readLoginHistoryCount(undefined)).toBe(0);
  });

  it('reads an invalid stored value as 0 and logs a warning', () => {
    [-1, LOGIN_HISTORY_MAX_COUNT + 1, 2.5].forEach((value) => expect(readLoginHistoryCount({ platform_login_history_count: value })).toBe(0));
    expect(logApp.warn).toHaveBeenCalledTimes(3);
  });

  it('accepts an edit of an integer in the range, as a number or a string', () => {
    [[0], [5], ['5'], [String(LOGIN_HISTORY_MAX_COUNT)]].forEach((values) => expect(() => checkLoginHistoryCountEdit(values)).not.toThrow());
  });

  it('refuses an edit out of the range or not an integer', () => {
    [[-1], [LOGIN_HISTORY_MAX_COUNT + 1], ['2.5'], ['abc'], [''], [], null, [1, 2]].forEach((values) => {
      expect(() => checkLoginHistoryCountEdit(values)).toThrow(`between 0 and ${LOGIN_HISTORY_MAX_COUNT}`);
    });
  });
});

describe('user login history', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(isEnterpriseEditionFromSettings).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_login_history_count: 3 } as any);
  });

  it('reads the last successful logins of the user only, newest first', async () => {
    vi.mocked(elRawSearch).mockResolvedValue({
      hits: {
        hits: [
          { _source: { internal_id: 'log-2', timestamp: '2026-11-25T10:00:00.000Z', context_data: { provider: 'local' } } },
          { _source: { internal_id: 'log-1', timestamp: '2026-11-24T10:00:00.000Z' } },
        ],
      },
    } as any);
    const logins = await findUserLoginHistory(context, user);
    expect(logins).toEqual([
      { id: 'log-2', timestamp: '2026-11-25T10:00:00.000Z', provider: 'local' },
      { id: 'log-1', timestamp: '2026-11-24T10:00:00.000Z', provider: null },
    ]);
    const [, , , query] = vi.mocked(elRawSearch).mock.calls[0];
    expect(query.size).toBe(3);
    expect(query.body.sort).toEqual([{ timestamp: 'desc' }]);
    expect(query.body.query.bool.filter).toEqual(expect.arrayContaining([
      { term: { 'event_scope.keyword': { value: 'login' } } },
      { term: { 'event_status.keyword': { value: 'success' } } },
      { term: { 'user_id.keyword': { value: 'user-1' } } },
    ]));
  });

  it('reads nothing without an Enterprise Edition licence', async () => {
    vi.mocked(isEnterpriseEditionFromSettings).mockReturnValue(false);
    expect(await findUserLoginHistory(context, user)).toEqual([]);
    expect(elRawSearch).not.toHaveBeenCalled();
  });

  it('reads nothing when the count is 0 or not set', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_login_history_count: 0 } as any);
    expect(await findUserLoginHistory(context, user)).toEqual([]);
    vi.mocked(getEntityFromCache).mockResolvedValue({} as any);
    expect(await findUserLoginHistory(context, user)).toEqual([]);
    expect(elRawSearch).not.toHaveBeenCalled();
  });
});
