import { afterEach, describe, expect, it, vi } from 'vitest';
import * as userDomain from '../../../src/modules/user/user-domain';
import * as access from '../../../src/utils/access';
import { canSubscriberStillAccess } from '../../../src/graphql/subscriptionWrapper';
import type { AuthUser } from '../../../src/types/user';

const instance = { id: 'run-1', internal_id: 'run-1', entity_type: 'Investigation-Run' };
// The snapshot a socket keeps from the moment it opened.
const snapshot = { id: 'user-1', allowed_marking: [{ internal_id: 'marking-red' }] } as unknown as AuthUser;
const context = { user: snapshot } as never;

describe('canSubscriberStillAccess', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('checks the access of the current user, not of the snapshot of the subscription', async () => {
    const current = { id: 'user-1', allowed_marking: [] } as unknown as AuthUser;
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValue(current);
    const check = vi.spyOn(access, 'isUserCanAccessStoreElement').mockResolvedValue(false);
    expect(await canSubscriberStillAccess(context, instance)).toBe(false);
    expect(check).toHaveBeenCalledWith(context, current, instance);
    check.mockResolvedValue(true);
    expect(await canSubscriberStillAccess(context, instance)).toBe(true);
  });

  it('stops the events of a subscriber that no longer exists', async () => {
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValue(undefined);
    const check = vi.spyOn(access, 'isUserCanAccessStoreElement').mockResolvedValue(true);
    expect(await canSubscriberStillAccess(context, instance)).toBe(false);
    expect(check).not.toHaveBeenCalled();
  });

  it('stops the events instead of throwing when the access cannot be read', async () => {
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockRejectedValue(new Error('Cache unavailable'));
    expect(await canSubscriberStillAccess(context, instance)).toBe(false);
    expect(await canSubscriberStillAccess({ user: null } as never, instance)).toBe(false);
  });
});
