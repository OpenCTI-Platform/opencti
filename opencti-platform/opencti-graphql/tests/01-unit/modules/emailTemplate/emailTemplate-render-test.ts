import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LOCKED_USER_EMAIL_TEMPLATE_INPUT } from '../../../../src/database/locked-user-email-template-input';
import { type LockedUserEmailData, renderEmailTemplate } from '../../../../src/modules/emailTemplate/emailTemplate-render';

const flags = vi.hoisted(() => ({ lockout: true }));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn((flag: string) => flag !== 'LOCAL_AUTH_LOCKOUT' || flags.lockout),
}));

// The recipient is an administrator, the locked user another account
const RECIPIENT = { name: 'admin', firstname: 'Ada', lastname: 'Admin', user_email: 'admin@opencti.io' };
const LOCKED_USER = { name: 'jdoe', firstname: 'John', lastname: 'Doe', user_email: 'jdoe@opencti.io' };
const LOCK_DATE = new Date('2026-11-13T16:25:00.000Z');
const temporaryLock: LockedUserEmailData = {
  lockedUser: LOCKED_USER,
  lock: { date: LOCK_DATE, attempts: 10, type: 'temporary', endDate: new Date('2026-11-13T16:40:00.000Z') },
};
const permanentLock: LockedUserEmailData = { lockedUser: LOCKED_USER, lock: { date: LOCK_DATE, attempts: 3, type: 'permanent' } };

const render = (templateBody: string, lockedUserData?: LockedUserEmailData) => renderEmailTemplate(templateBody, {
  platformUrl: 'https://opencti.example.com',
  user: RECIPIENT,
  organizationNames: ['Filigran'],
  lockedUserData,
});

describe('Email template rendering', () => {
  beforeEach(() => {
    flags.lockout = true;
  });

  it('should render the recipient and the platform variables', async () => {
    const html = await render('$user.firstname $user.lastname ($user.name, $user.user_email) of $user.objectOrganization on $settings.platform_url');
    expect(html).toEqual('Ada Admin (admin, admin@opencti.io) of Filigran on https://opencti.example.com');
  });

  it('should render the locked user and the date of a temporary lock, with its end', async () => {
    const html = await render('$locked_user.firstname $locked_user.lastname ($locked_user.name, $locked_user.user_email) | $lock.date | $lock.attempts | $lock.type | $lock.end_date | $lock.unlock', temporaryLock);
    expect(html).toEqual('John Doe (jdoe, jdoe@opencti.io) | 2026-11-13 16:25 UTC | 10 | temporary | 2026-11-13 16:40 UTC | The account is locked until 2026-11-13 16:40 UTC.');
  });

  it('should say that an administrator must unlock a permanent lock, without any end', async () => {
    const html = await render('$lock.type | $lock.end_date | $lock.unlock', permanentLock);
    expect(html).toEqual('permanent |  | The account is locked until an administrator unlocks it.');
  });

  it('should keep the recipient and the locked user apart', async () => {
    const html = await render('$user.name / $locked_user.name / $user.user_email / $locked_user.user_email', temporaryLock);
    expect(html).toEqual('admin / jdoe / admin@opencti.io / jdoe@opencti.io');
  });

  it('should escape the locked user data', async () => {
    const lockedUserData = { ...temporaryLock, lockedUser: { ...LOCKED_USER, name: '<script>alert(1)</script>' } };
    const html = await render('$locked_user.name', lockedUserData);
    expect(html).toEqual('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('should render the lock variables empty without any lock, such as in a test email', async () => {
    const html = await render('[$locked_user.name][$lock.date][$lock.unlock]');
    expect(html).toEqual('[][][]');
  });

  it('should keep the lock variables as written without the feature flag', async () => {
    flags.lockout = false;
    const html = await render('$user.name $locked_user.name $lock.unlock', temporaryLock);
    expect(html).toEqual('admin $locked_user.name $lock.unlock');
  });

  it('should render the built-in template with the locked user and the date of the lock', async () => {
    const html = await render(LOCKED_USER_EMAIL_TEMPLATE_INPUT.template_body, temporaryLock);
    expect(html).toContain('Dear Ada Admin,');
    expect(html).toContain('The account of <strong>jdoe</strong> (jdoe@opencti.io) has been locked on 2026-11-13 16:25 UTC, after 10 failed authentication attempts.');
    expect(html).toContain('The account is locked until 2026-11-13 16:40 UTC.');
    expect(html).toContain('Platform url: https://opencti.example.com');
    expect(html).not.toContain('$');
  });
});
