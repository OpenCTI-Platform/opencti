import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { loadLocalAuthLockRecipients, selectLocalAuthLockRecipients } from '../../../src/domain/local-auth-lockout-notification';
import type { BasicStoreSettings } from '../../../src/types/settings';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { BYPASS, SETTINGS_SETACCESSES, SETTINGS_SETLABELS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../src/utils/access';

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
  getEntitiesListFromCache: vi.fn(),
}));

const ORGANIZATION = { internal_id: 'organization-locked-user' };
const OTHER_ORGANIZATION = { internal_id: 'organization-other' };

const buildUser = (id: string, user: Partial<AuthUser> = {}) => ({
  id,
  internal_id: id,
  name: id,
  user_email: `${id}@opencti.io`,
  account_status: 'Active',
  user_service_account: false,
  capabilities: [],
  organizations: [],
  administrated_organizations: [],
  ...user,
}) as unknown as AuthUser;
const capabilities = (...names: string[]) => names.map((name) => ({ name }));

const LOCKED_USER = buildUser('locked', { organizations: [ORGANIZATION] } as Partial<AuthUser>);
const ACCESS_ADMIN = buildUser('access-admin', { capabilities: capabilities(SETTINGS_SETACCESSES) });
const BYPASS_ADMIN = buildUser('bypass-admin', { capabilities: capabilities(BYPASS) });
const ORGANIZATION_ADMIN = buildUser('organization-admin', {
  capabilities: capabilities(VIRTUAL_ORGANIZATION_ADMIN),
  administrated_organizations: [ORGANIZATION],
} as Partial<AuthUser>);
const OTHER_ORGANIZATION_ADMIN = buildUser('other-organization-admin', {
  capabilities: capabilities(VIRTUAL_ORGANIZATION_ADMIN),
  administrated_organizations: [OTHER_ORGANIZATION],
} as Partial<AuthUser>);
const LABELS_MANAGER = buildUser('labels-manager', { capabilities: capabilities(SETTINGS_SETLABELS) });

const ids = (users: AuthUser[]) => users.map((user) => user.id);
const select = (platformUsers: AuthUser[], options: { withOrganizationAdmins?: boolean; maxRecipients?: number } = {}) => {
  const { withOrganizationAdmins = false, maxRecipients = 500 } = options;
  return ids(selectLocalAuthLockRecipients(platformUsers, LOCKED_USER, { withOrganizationAdmins, maxRecipients }));
};

describe('Local authentication lockout - recipients of the lock email', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should send the email to the administrators of the accesses, BYPASS included', () => {
    expect(select([ACCESS_ADMIN, BYPASS_ADMIN, LABELS_MANAGER, LOCKED_USER])).toEqual(['access-admin', 'bypass-admin']);
  });

  it('should leave out the inactive accounts, the service accounts and the accounts without an email', () => {
    const lockedAdmin = buildUser('locked-admin', { capabilities: capabilities(SETTINGS_SETACCESSES), account_status: 'Locked' });
    const expiredAdmin = buildUser('expired-admin', { capabilities: capabilities(SETTINGS_SETACCESSES), account_status: 'Expired' });
    const serviceAccount = buildUser('service-account', { capabilities: capabilities(BYPASS), user_service_account: true });
    const withoutEmail = buildUser('without-email', { capabilities: capabilities(BYPASS), user_email: '' });
    expect(select([ACCESS_ADMIN, lockedAdmin, expiredAdmin, serviceAccount, withoutEmail])).toEqual(['access-admin']);
  });

  it('should leave out the locked user, even when it is an administrator', () => {
    const lockedAdmin = buildUser('locked', { capabilities: capabilities(BYPASS) });
    expect(ids(selectLocalAuthLockRecipients([lockedAdmin, ACCESS_ADMIN], lockedAdmin, { withOrganizationAdmins: false, maxRecipients: 500 })))
      .toEqual(['access-admin']);
  });

  it('should add the administrators of an organization of the locked user with the organization segregation', () => {
    const platformUsers = [ORGANIZATION_ADMIN, OTHER_ORGANIZATION_ADMIN, ACCESS_ADMIN];
    expect(select(platformUsers, { withOrganizationAdmins: true })).toEqual(['access-admin', 'organization-admin']);
  });

  it('should not add the administrators of an organization without the organization segregation', () => {
    expect(select([ORGANIZATION_ADMIN, ACCESS_ADMIN])).toEqual(['access-admin']);
  });

  it('should send a single email to an administrator of the accesses who also administrates the organization', () => {
    const bothAdmin = buildUser('both-admin', {
      capabilities: capabilities(SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN),
      administrated_organizations: [ORGANIZATION],
    } as Partial<AuthUser>);
    expect(select([bothAdmin, ORGANIZATION_ADMIN], { withOrganizationAdmins: true })).toEqual(['both-admin', 'organization-admin']);
  });

  it('should keep the administrators of the accesses first under the limit, and log the others left out', () => {
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => undefined);
    const platformUsers = [ORGANIZATION_ADMIN, ACCESS_ADMIN, BYPASS_ADMIN];
    expect(select(platformUsers, { withOrganizationAdmins: true, maxRecipients: 2 })).toEqual(['access-admin', 'bypass-admin']);
    expect(warn).toHaveBeenCalledOnce();
  });
});

describe('Local authentication lockout - loading the recipients of the lock email', () => {
  const context = {} as AuthContext;
  const mockPlatform = (settings: Partial<BasicStoreSettings>, platformUsers: AuthUser[]) => {
    vi.mocked(getEntityFromCache).mockResolvedValue(settings as BasicStoreSettings);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue(platformUsers);
  };

  it('should add the administrators of an organization when the settings hold a platform organization', async () => {
    mockPlatform({ platform_organization: 'platform-organization' }, [ACCESS_ADMIN, ORGANIZATION_ADMIN]);
    expect(ids(await loadLocalAuthLockRecipients(context, LOCKED_USER))).toEqual(['access-admin', 'organization-admin']);
  });

  it('should not add the administrators of an organization without a platform organization', async () => {
    mockPlatform({}, [ACCESS_ADMIN, ORGANIZATION_ADMIN]);
    expect(ids(await loadLocalAuthLockRecipients(context, LOCKED_USER))).toEqual(['access-admin']);
  });
});
