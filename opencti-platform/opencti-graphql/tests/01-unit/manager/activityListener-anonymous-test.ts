import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));
vi.mock('../../../src/database/stream/stream-handler', () => ({ storeActivityEvent: vi.fn() }));

import activityListener from '../../../src/manager/activityListener';
import { publishUserAction, type UserAction } from '../../../src/listener/UserActionListener';
import { getEntityFromCache } from '../../../src/database/cache';
import { storeActivityEvent } from '../../../src/database/stream/stream-handler';
import type { AuthUser } from '../../../src/types/user';

const user = { id: 'user-id', origin: { socket: 'query', user_id: 'user-id' } } as unknown as AuthUser;

// The access to a disabled feature is refused before any authentication check: the action can come without a user
const unauthorizedRead = (actionUser: AuthUser | undefined) => ({
  user: actionUser,
  event_type: 'read',
  event_scope: 'unauthorized',
  event_access: 'administration',
  status: 'error',
  context_data: { operation: 'FlaggedQuery', input: {} },
}) as unknown as UserAction;

describe('Activity listener: action without a user', () => {
  beforeEach(async () => {
    vi.resetAllMocks();
    vi.mocked(getEntityFromCache).mockResolvedValue({ valid_enterprise_edition: true, activity_listeners_users: [] } as never);
    await activityListener.start();
  });

  afterEach(async () => {
    await activityListener.shutdown();
  });

  it('ignores an action without a user', async () => {
    await expect(publishUserAction(unauthorizedRead(undefined))).resolves.toBeDefined();
    expect(storeActivityEvent).not.toHaveBeenCalled();
  });

  it('logs the unauthorized read of a user', async () => {
    await publishUserAction(unauthorizedRead(user));
    expect(storeActivityEvent).toHaveBeenCalledTimes(1);
    expect(storeActivityEvent).toHaveBeenCalledWith(expect.objectContaining({
      type: 'read',
      event_scope: 'unauthorized',
      status: 'error',
      origin: user.origin,
      message: 'tries an `unauthorized read`',
    }));
  });
});
