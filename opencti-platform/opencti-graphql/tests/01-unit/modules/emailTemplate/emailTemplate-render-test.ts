import { describe, expect, it } from 'vitest';
import { LOCKED_USER_EMAIL_TEMPLATE_INPUT } from '../../../../src/database/locked-user-email-template-input';
import { buildTemplateRecipient, type LockedUserEmailData, type LockedUserLock, renderEmailTemplate } from '../../../../src/modules/emailTemplate/emailTemplate-render';

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

  // Checked by the type checking of the tests: without its end, $lock.unlock could not say until when the account is locked
  it('should not accept a temporary lock without its end', () => {
    // @ts-expect-error a temporary lock always has its end
    const lock: LockedUserLock = { date: LOCK_DATE, attempts: 10, type: 'temporary' };
    expect(lock.type).toEqual('temporary');
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

  it('should render the built-in template with the locked user and the date of the lock', async () => {
    const html = await render(LOCKED_USER_EMAIL_TEMPLATE_INPUT.template_body, temporaryLock);
    expect(html).toContain('Dear Ada Admin,');
    expect(html).toContain('The account of <strong>jdoe</strong> (jdoe@opencti.io) has been locked on 2026-11-13 16:25 UTC, after 10 failed authentication attempts.');
    expect(html).toContain('The account is locked until 2026-11-13 16:40 UTC.');
    expect(html).toContain('Platform url: https://opencti.example.com');
    expect(html).not.toContain('$');
  });
});

describe('Email template recipient', () => {
  it('should keep only the fields a template can show, without any API token', () => {
    const recipient = buildTemplateRecipient({ ...RECIPIENT, api_token: 'secret', password: 'hash', account_lock_after_date: undefined } as Parameters<typeof buildTemplateRecipient>[0]);
    expect(recipient).toEqual({ ...RECIPIENT, api_token: '', account_lock_after_date: '' });
  });

  it('should show the expiration date of the account as a day, from a date or its ISO string', () => {
    expect(buildTemplateRecipient({ account_lock_after_date: '2027-03-01T10:00:00.000Z' }).account_lock_after_date).toEqual('2027-03-01');
    expect(buildTemplateRecipient({ account_lock_after_date: new Date('2027-03-01T10:00:00.000Z') }).account_lock_after_date).toEqual('2027-03-01');
  });
});
