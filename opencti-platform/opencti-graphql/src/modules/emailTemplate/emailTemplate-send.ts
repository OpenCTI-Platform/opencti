import { sendMail, smtpComputeFrom } from '../../database/smtp';
import { buildTemplateRecipient, type LockedUserEmailData, renderEmailTemplate } from './emailTemplate-render';
import type { BasicStoreEntityEmailTemplate } from './emailTemplate-types';

export type EmailTemplateContent = Pick<BasicStoreEntityEmailTemplate, 'email_object' | 'sender_email' | 'template_body'>;
export type EmailTemplateRecipient = {
  id: string;
  user_email: string;
  organizations?: Array<{ name?: string }>;
  account_lock_after_date?: string | Date | null;
};

type SendEmailTemplateOptions = {
  platformUrl: string;
  // The category of the sent emails metric
  category: string;
  // The token generated for a template that asks for $user.api_token: empty without it
  apiToken?: string;
  lockedUserData?: LockedUserEmailData;
};

// Renders the template for its recipient, the $user variables, and sends it to this recipient only
export const sendEmailTemplateToRecipient = async (template: EmailTemplateContent, recipient: EmailTemplateRecipient, options: SendEmailTemplateOptions) => {
  const { platformUrl, category, apiToken, lockedUserData } = options;
  const html = await renderEmailTemplate(template.template_body, {
    platformUrl,
    user: { ...buildTemplateRecipient(recipient), api_token: apiToken ?? '' },
    organizationNames: (recipient.organizations ?? []).map((organization) => organization.name ?? ''),
    lockedUserData,
  });
  const sendMailArgs = {
    from: await smtpComputeFrom(template.sender_email),
    to: recipient.user_email,
    subject: template.email_object,
    html,
  };
  await sendMail(sendMailArgs, { identifier: `user-${recipient.id}`, category });
};
