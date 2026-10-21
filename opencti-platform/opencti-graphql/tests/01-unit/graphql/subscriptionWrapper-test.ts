import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as userDomain from '../../../src/modules/user/user-domain';
import * as access from '../../../src/utils/access';
import * as cache from '../../../src/database/cache';
import { canSubscriberStillAccess } from '../../../src/graphql/subscriptionWrapper';
import type { AuthUser } from '../../../src/types/user';

const instance = { id: 'run-1', internal_id: 'run-1', entity_type: 'Investigation-Run' };
// The snapshot a socket keeps from the moment it opened.
const snapshot = { id: 'user-1', allowed_marking: [{ internal_id: 'marking-red' }] } as unknown as AuthUser;
const context = { user: snapshot, user_inside_platform_organization: true } as never;

describe('canSubscriberStillAccess', () => {
  beforeEach(() => {
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ platform_organization: 'org-platform' } as never);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('checks the access of the current user and platform organization membership, not of the snapshot of the subscription', async () => {
    const current = { id: 'user-1', allowed_marking: [] } as unknown as AuthUser;
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValue(current);
    vi.spyOn(userDomain, 'isUserAccountValid').mockReturnValue(true);
    const membership = vi.spyOn(access, 'isUserInPlatformOrganization').mockReturnValue(false);
    const check = vi.spyOn(access, 'isUserCanAccessStoreElement').mockResolvedValue(false);
    const subscription = { user: { ...snapshot, origin: { socket: 'subscription' } }, user_inside_platform_organization: true } as Record<string, unknown>;
    expect(await canSubscriberStillAccess(subscription, instance)).toBe(false);
    expect(membership).toHaveBeenCalledWith(current, { platform_organization: 'org-platform' });
    const expectedUser = expect.objectContaining({ allowed_marking: [], origin: { socket: 'subscription' } });
    expect(check).toHaveBeenCalledWith(expect.objectContaining({ user: expectedUser, user_inside_platform_organization: false }), expectedUser, instance);
    // A refused event leaves the subscription context as it was.
    expect(subscription.user).toMatchObject({ allowed_marking: [{ internal_id: 'marking-red' }] });
    check.mockResolvedValue(true);
    expect(await canSubscriberStillAccess(subscription, instance)).toBe(true);
    // An event that passes is resolved with the current identity of the subscriber.
    expect(subscription).toMatchObject({ user: { allowed_marking: [], origin: { socket: 'subscription' } }, user_inside_platform_organization: false });
    expect(subscription.batch).toBeDefined();
  });

  it('stops the events of a subscriber that lost a capability the subscription requires', async () => {
    const current = { id: 'user-1', capabilities: [{ name: 'SETTINGS_SETACCESSES' }] } as unknown as AuthUser;
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValue(current);
    vi.spyOn(userDomain, 'isUserAccountValid').mockReturnValue(true);
    const check = vi.spyOn(access, 'isUserCanAccessStoreElement').mockResolvedValue(true);
    expect(await canSubscriberStillAccess(context, instance, ['KNOWLEDGE'])).toBe(false);
    expect(check).not.toHaveBeenCalled();
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValue({ ...current, capabilities: [{ name: 'KNOWLEDGE' }] } as unknown as AuthUser);
    expect(await canSubscriberStillAccess({ user: snapshot }, instance, ['KNOWLEDGE'])).toBe(true);
  });

  it('stops the events of a subscriber whose account was locked or expired since the socket opened', async () => {
    const locked = { id: 'user-1', account_status: 'Locked', organizations: [], capabilities: [] } as unknown as AuthUser;
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValue(locked);
    const check = vi.spyOn(access, 'isUserCanAccessStoreElement').mockResolvedValue(true);
    expect(await canSubscriberStillAccess(context, instance)).toBe(false);
    expect(check).not.toHaveBeenCalled();
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

describe('isUserAccountValid', () => {
  const settings = { platform_organization: null } as never;
  const account = (fields: Record<string, unknown>) => ({ id: 'user-1', account_status: 'Active', organizations: [], capabilities: [], ...fields }) as unknown as AuthUser;

  it('accepts an active account and refuses one the authentication refuses', () => {
    expect(userDomain.isUserAccountValid(account({}), settings)).toBe(true);
    expect(userDomain.isUserAccountValid(account({ account_status: 'Locked' }), settings)).toBe(false);
    expect(userDomain.isUserAccountValid(account({ account_lock_after_date: '2020-01-01T00:00:00.000Z' }), settings)).toBe(false);
    expect(userDomain.isUserAccountValid(account({ password_valid_until: '2020-01-01T00:00:00.000Z' }), settings)).toBe(false);
  });
});
