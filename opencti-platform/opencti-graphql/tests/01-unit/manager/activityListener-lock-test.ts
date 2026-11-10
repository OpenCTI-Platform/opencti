import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));
vi.mock('../../../src/database/stream/stream-handler', () => ({ storeActivityEvent: vi.fn() }));

import activityListener, { EVENT_SCOPE_VALUES } from '../../../src/manager/activityListener';
import { publishUserAction, type UserLockAction } from '../../../src/listener/UserActionListener';
import { getEntityFromCache } from '../../../src/database/cache';
import { storeActivityEvent } from '../../../src/database/stream/stream-handler';
import type { AuthUser } from '../../../src/types/user';

const user = { id: 'user-id', origin: { socket: 'query', ip: '10.0.0.7', user_id: 'user-id' } } as unknown as AuthUser;

const lockAction = (contextData: UserLockAction['context_data']): UserLockAction => ({
  user,
  event_type: 'authentication',
  event_scope: 'lock',
  event_access: 'administration',
  status: 'error',
  context_data: contextData,
});

describe('Activity listener: local authentication lock', () => {
  beforeEach(async () => {
    vi.resetAllMocks();
    // No user listened: a lock is an administration event, logged for every user
    vi.mocked(getEntityFromCache).mockResolvedValue({ valid_enterprise_edition: true, activity_listeners_users: [] } as never);
    await activityListener.start();
  });

  afterEach(async () => {
    await activityListener.shutdown();
  });

  it('offers the lock scope in the activity filters', () => {
    // The test configuration enables every feature flag, including LOCAL_AUTH_LOCKOUT
    expect(EVENT_SCOPE_VALUES).toContain('lock');
  });

  it('logs a temporary lock with its duration and the max attempts', async () => {
    await publishUserAction(lockAction({ username: 'user@opencti.io', lock_type: 'temporary', lock_duration: 15, max_attempts: 10, source: 'form' }));
    expect(storeActivityEvent).toHaveBeenCalledTimes(1);
    expect(storeActivityEvent).toHaveBeenCalledWith(expect.objectContaining({
      type: 'authentication',
      event_scope: 'lock',
      event_access: 'administration',
      status: 'error',
      origin: user.origin,
      message: 'detects `account lock` for `user@opencti.io`: locked for `15 minutes` after `10` failed authentication attempts',
      data: { username: 'user@opencti.io', lock_type: 'temporary', lock_duration: 15, max_attempts: 10, source: 'form' },
    }));
  });

  it('logs a permanent lock until an administrator unlocks the account', async () => {
    await publishUserAction(lockAction({ username: 'admin@opencti.io', lock_type: 'permanent', max_attempts: 3, source: 'mfa' }));
    expect(storeActivityEvent).toHaveBeenCalledWith(expect.objectContaining({
      event_scope: 'lock',
      message: 'detects `account lock` for `admin@opencti.io`: locked until an administrator unlocks it after `3` failed authentication attempts',
    }));
  });

  it('logs nothing when the enterprise edition is not active', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ valid_enterprise_edition: false } as never);
    await publishUserAction(lockAction({ username: 'user@opencti.io', lock_type: 'temporary', lock_duration: 15, max_attempts: 10, source: 'form' }));
    expect(storeActivityEvent).not.toHaveBeenCalled();
  });
});
