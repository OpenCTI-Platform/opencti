import { describe, it, expect } from 'vitest';
import { isUserInPlatformOrganization, SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthUser } from '../../../../src/types/user';
import type { BasicStoreSettings } from '../../../../src/types/settings';

const buildUser = (overrides: Partial<AuthUser> = {}): AuthUser => ({
  ...SYSTEM_USER,
  id: 'user-1',
  internal_id: 'user-1',
  capabilities: [],
  user_service_account: false,
  organizations: [],
  ...overrides,
});

describe('isUserInPlatformOrganization', () => {
  it('returns false when platform_organization is set and the user is not a member', () => {
    const settings = { platform_organization: 'organization--platform-id' } as BasicStoreSettings;
    const user = buildUser({
      organizations: [{ internal_id: 'organization--other-id' } as any],
    });

    expect(isUserInPlatformOrganization(user, settings)).toBe(false);
  });

  it('returns true when platform_organization is set and the user IS a member', () => {
    const settings = { platform_organization: 'organization--platform-id' } as BasicStoreSettings;
    const user = buildUser({
      organizations: [{ internal_id: 'organization--platform-id' } as any],
    });

    expect(isUserInPlatformOrganization(user, settings)).toBe(true);
  });

  it('returns true when no platform_organization is configured, regardless of membership', () => {
    const settings = { platform_organization: null } as unknown as BasicStoreSettings;
    const user = buildUser({ organizations: [] });

    expect(isUserInPlatformOrganization(user, settings)).toBe(true);
  });

  it('returns true for a BYPASS user even when not a member of the platform organization', () => {
    const settings = { platform_organization: 'organization--platform-id' } as BasicStoreSettings;
    const user = buildUser({
      capabilities: [{ name: 'BYPASS' }] as any,
      organizations: [],
    });

    expect(isUserInPlatformOrganization(user, settings)).toBe(true);
  });

  it('returns true for a service account user even when not a member', () => {
    const settings = { platform_organization: 'organization--platform-id' } as BasicStoreSettings;
    const user = buildUser({
      user_service_account: true,
      organizations: [],
    });

    expect(isUserInPlatformOrganization(user, settings)).toBe(true);
  });
});
