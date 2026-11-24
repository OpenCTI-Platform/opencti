import { beforeEach, describe, expect, it, vi } from 'vitest';
import { sendMail, smtpComputeFrom } from '../../../../src/database/smtp';
import { sendEmailTemplateToRecipient } from '../../../../src/modules/emailTemplate/emailTemplate-send';
import type { LockedUserEmailData } from '../../../../src/modules/emailTemplate/emailTemplate-render';

vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => true),
}));

vi.mock('../../../../src/database/smtp', () => ({
  sendMail: vi.fn(),
  smtpComputeFrom: vi.fn(async (from?: string) => `${from} <no-reply@opencti.io>`),
}));

const TEMPLATE = {
  email_object: 'Hello',
  sender_email: 'OpenCTI Administrator',
  template_body: '$user.firstname of $user.objectOrganization [$user.api_token] on $settings.platform_url',
};
const RECIPIENT = {
  id: 'recipient-id',
  name: 'admin',
  firstname: 'Ada',
  user_email: 'admin@opencti.io',
  organizations: [{ name: 'Filigran' }, { name: 'OpenCTI' }],
};
const OPTIONS = { platformUrl: 'https://opencti.example.com', category: 'user-notification' };
const sentEmail = () => vi.mocked(sendMail).mock.calls[0];

describe('Email template send', () => {
  beforeEach(() => {
    vi.mocked(sendMail).mockReset();
    vi.mocked(smtpComputeFrom).mockClear();
  });

  it('should render the template for its recipient and send it to this recipient only', async () => {
    await sendEmailTemplateToRecipient(TEMPLATE, RECIPIENT, OPTIONS);
    expect(sendMail).toHaveBeenCalledOnce();
    const [args, meterMetadata] = sentEmail();
    expect(args).toEqual({
      from: 'OpenCTI Administrator <no-reply@opencti.io>',
      to: 'admin@opencti.io',
      subject: 'Hello',
      html: 'Ada of Filigran, OpenCTI [] on https://opencti.example.com',
    });
    expect(meterMetadata).toEqual({ identifier: 'user-recipient-id', category: 'user-notification' });
    expect(smtpComputeFrom).toHaveBeenCalledWith('OpenCTI Administrator');
  });

  it('should render the token generated for a template that asks for it', async () => {
    await sendEmailTemplateToRecipient(TEMPLATE, RECIPIENT, { ...OPTIONS, apiToken: 'generated-token' });
    expect(sentEmail()[0].html).toContain('[generated-token]');
  });

  it('should render the locked user and the lock', async () => {
    const lockedUserData: LockedUserEmailData = {
      lockedUser: { name: 'jdoe', user_email: 'jdoe@opencti.io' },
      lock: { date: new Date('2026-11-18T10:00:00.000Z'), attempts: 3, type: 'permanent' },
    };
    const template = { ...TEMPLATE, template_body: '$user.firstname: $locked_user.name, $lock.attempts, $lock.unlock' };
    await sendEmailTemplateToRecipient(template, RECIPIENT, { ...OPTIONS, category: 'local-auth-lock', lockedUserData });
    const [args, meterMetadata] = sentEmail();
    expect(args.html).toEqual('Ada: jdoe, 3, The account is locked until an administrator unlocks it.');
    expect(meterMetadata.category).toEqual('local-auth-lock');
  });

  it('should render a recipient without any organization', async () => {
    await sendEmailTemplateToRecipient(TEMPLATE, { ...RECIPIENT, organizations: undefined }, OPTIONS);
    expect(sentEmail()[0].html).toEqual('Ada of  [] on https://opencti.example.com');
  });

  it('should fail when the email cannot be sent, so that its caller decides', async () => {
    vi.mocked(sendMail).mockRejectedValueOnce(new Error('SMTP down'));
    await expect(sendEmailTemplateToRecipient(TEMPLATE, RECIPIENT, OPTIONS)).rejects.toThrow('SMTP down');
  });
});
