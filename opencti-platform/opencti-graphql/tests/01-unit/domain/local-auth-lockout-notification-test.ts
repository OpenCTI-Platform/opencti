import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { LOCKED_USER_EMAIL_TEMPLATE_INPUT } from '../../../src/database/locked-user-email-template-input';
import {
  buildLocalAuthLockEmailData,
  loadLocalAuthLockEmailTemplate,
  loadLocalAuthLockRecipients,
  selectLocalAuthLockRecipients,
  sendLocalAuthLockEmails,
} from '../../../src/domain/local-auth-lockout-notification';
import { sendMail } from '../../../src/database/smtp';
import { findLockedUserEmailTemplate } from '../../../src/modules/emailTemplate/emailTemplate-domain';
import type { BasicStoreEntityEmailTemplate } from '../../../src/modules/emailTemplate/emailTemplate-types';
import type { BasicStoreSettings } from '../../../src/types/settings';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { BYPASS, SETTINGS_SETACCESSES, SETTINGS_SETLABELS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../src/utils/access';

vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => true),
}));

vi.mock('../../../src/database/smtp', () => ({
  sendMail: vi.fn(),
  smtpComputeFrom: vi.fn(async (from?: string) => `${from} <no-reply@opencti.io>`),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
  getEntitiesListFromCache: vi.fn(),
}));

vi.mock('../../../src/modules/emailTemplate/emailTemplate-domain', () => ({
  findLockedUserEmailTemplate: vi.fn(),
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
    // Its expiration date has passed, but the expiration manager has not set it to Expired yet
    const pastExpirationAdmin = buildUser('past-expiration-admin', { capabilities: capabilities(BYPASS), account_lock_after_date: new Date('2020-01-01') });
    expect(select([ACCESS_ADMIN, lockedAdmin, expiredAdmin, serviceAccount, withoutEmail, pastExpirationAdmin])).toEqual(['access-admin']);
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

describe('Local authentication lockout - template of the lock email', () => {
  const context = {} as AuthContext;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should use the built-in template as the administrators edited it', async () => {
    const editedTemplate = { ...LOCKED_USER_EMAIL_TEMPLATE_INPUT, email_object: 'Account locked', template_body: '<p>$locked_user.name</p>' };
    vi.mocked(findLockedUserEmailTemplate).mockResolvedValue(editedTemplate as BasicStoreEntityEmailTemplate);
    const template = await loadLocalAuthLockEmailTemplate(context);
    expect(template).toMatchObject({ email_object: 'Account locked', template_body: '<p>$locked_user.name</p>' });
  });

  it('should send the default content, and log it, when the built-in template was deleted', async () => {
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => undefined);
    vi.mocked(findLockedUserEmailTemplate).mockResolvedValue(undefined);
    const template = await loadLocalAuthLockEmailTemplate(context);
    expect(template).toMatchObject({
      email_object: LOCKED_USER_EMAIL_TEMPLATE_INPUT.email_object,
      sender_email: LOCKED_USER_EMAIL_TEMPLATE_INPUT.sender_email,
      template_body: LOCKED_USER_EMAIL_TEMPLATE_INPUT.template_body,
    });
    expect(warn).toHaveBeenCalledOnce();
  });
});

describe('Local authentication lockout - data of the lock email', () => {
  const LOCK_DATE = new Date('2026-11-18T10:00:00.000Z');
  const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;
  const lockedAccount = { name: 'jdoe', firstname: 'John', lastname: 'Doe', user_email: 'jdoe@opencti.io' };

  it('should end a temporary lock after the lockout duration', () => {
    const data = buildLocalAuthLockEmailData(lockedAccount, { lockType: 'temporary', maxAttempts: 10, remainingMs: FIFTEEN_MINUTES_MS }, LOCK_DATE);
    expect(data).toEqual({
      lockedUser: lockedAccount,
      lock: { date: LOCK_DATE, attempts: 10, type: 'temporary', endDate: new Date('2026-11-18T10:15:00.000Z') },
    });
  });

  it('should give no end to a permanent lock', () => {
    const data = buildLocalAuthLockEmailData(lockedAccount, { lockType: 'permanent', maxAttempts: 3, remainingMs: 0 }, LOCK_DATE);
    expect(data.lock).toEqual({ date: LOCK_DATE, attempts: 3, type: 'permanent' });
  });

  it('should keep only the name and the email of the locked user', () => {
    const lockedUser = { ...buildUser('jdoe', { capabilities: capabilities(BYPASS) }), firstname: 'John', lastname: 'Doe' };
    const data = buildLocalAuthLockEmailData(lockedUser, { lockType: 'permanent', maxAttempts: 3, remainingMs: 0 }, LOCK_DATE);
    expect(data.lockedUser).toEqual({ name: 'jdoe', firstname: 'John', lastname: 'Doe', user_email: 'jdoe@opencti.io' });
  });

  it('should date the lock now by default', () => {
    vi.useFakeTimers({ now: LOCK_DATE });
    try {
      const data = buildLocalAuthLockEmailData(lockedAccount, { lockType: 'permanent', maxAttempts: 3, remainingMs: 0 });
      expect(data.lock.date).toEqual(LOCK_DATE);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Local authentication lockout - sending the lock email', () => {
  const context = {} as AuthContext;
  const ADA = buildUser('ada', { capabilities: capabilities(SETTINGS_SETACCESSES), firstname: 'Ada', lastname: 'Admin' } as Partial<AuthUser>);
  const GRACE = buildUser('grace', { capabilities: capabilities(BYPASS), firstname: 'Grace', lastname: 'Hopper' } as Partial<AuthUser>);
  const LOCKED = { ...LOCKED_USER, firstname: 'John', lastname: 'Doe' };
  const temporaryLock = { lockType: 'temporary' as const, maxAttempts: 10, remainingMs: 15 * 60 * 1000 };

  const mockPlatform = (platformUsers: AuthUser[], template?: Partial<BasicStoreEntityEmailTemplate>) => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_url: 'https://opencti.example.com' } as BasicStoreSettings);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue(platformUsers);
    vi.mocked(findLockedUserEmailTemplate).mockResolvedValue({ ...LOCKED_USER_EMAIL_TEMPLATE_INPUT, ...template } as BasicStoreEntityEmailTemplate);
  };
  const sentEmails = () => vi.mocked(sendMail).mock.calls.map(([args]) => args);

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.mocked(sendMail).mockReset();
  });

  it('should send one email per administrator, rendered for its recipient', async () => {
    mockPlatform([ADA, GRACE, LOCKED]);
    await sendLocalAuthLockEmails(context, LOCKED, temporaryLock);
    const emails = sentEmails();
    expect(emails.map(({ to }) => to)).toEqual(['ada@opencti.io', 'grace@opencti.io']);
    expect(emails[0]).toMatchObject({ from: 'OpenCTI Administrator <no-reply@opencti.io>', subject: LOCKED_USER_EMAIL_TEMPLATE_INPUT.email_object });
    expect(emails[0].html).toContain('Dear Ada Admin,');
    expect(emails[1].html).toContain('Dear Grace Hopper,');
    expect(emails[0].html).toContain('The account of <strong>locked</strong> (locked@opencti.io) has been locked on');
    expect(emails[0].html).toContain('after 10 failed authentication attempts.');
    expect(emails[0].html).toContain('Platform url: https://opencti.example.com');
  });

  it('should never give an API token of the recipient', async () => {
    mockPlatform([ADA], { template_body: '[$user.api_token]' });
    await sendLocalAuthLockEmails(context, LOCKED, temporaryLock);
    expect(sentEmails()[0].html).toEqual('[]');
  });

  it('should keep sending to the other administrators when an email fails', async () => {
    const error = vi.spyOn(logApp, 'error').mockImplementation(() => undefined);
    mockPlatform([ADA, GRACE]);
    vi.mocked(sendMail).mockRejectedValueOnce(new Error('SMTP down'));
    await sendLocalAuthLockEmails(context, LOCKED, temporaryLock);
    expect(sentEmails().map(({ to }) => to)).toEqual(['ada@opencti.io', 'grace@opencti.io']);
    expect(error).toHaveBeenCalledOnce();
    expect(error.mock.calls[0][1]).toMatchObject({ recipient_id: 'ada', locked_user_id: 'locked' });
  });

  it('should send nothing, and log it, when no administrator can get the email', async () => {
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => undefined);
    mockPlatform([LOCKED, LABELS_MANAGER]);
    await sendLocalAuthLockEmails(context, LOCKED, temporaryLock);
    expect(sendMail).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledOnce();
  });
});
