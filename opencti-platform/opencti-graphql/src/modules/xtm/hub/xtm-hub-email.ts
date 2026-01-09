import conf, { getBaseUrl, logApp } from '../../../config/conf';
import type { AuthContext, AuthUser } from '../../../types/user';
import { findUserWithCapabilities } from '../../../domain/user';
import { BYPASS, HUB_REGISTRATION_MANAGER_USER, SETTINGS_SETMANAGEXTMHUB } from '../../../utils/access';
import type { BasicStoreSettings } from '../../../types/settings';
import { OCTI_EMAIL_TEMPLATE } from '../../../utils/emailTemplates/octiEmailTemplate';
import type { SendMailArgs } from '../../../types/smtp';
import { sendMail, smtpComputeFrom } from '../../../database/smtp';
import { safeRender } from '../../../utils/safeEjs.client';
import { sanitizeSettings } from '../../../utils/templateContextSanitizer';

const MAX_EMAIL_LIST_SIZE = conf.get('smtp:email_max_cc_size') || 500;
const TO_EMAIL = conf.get('xtm:xtmhub_to_email') || 'no-reply@filigran.io';
const EMAIL_BODY = `
  <p>We wanted to inform you that the connectivity between OpenCTI and the XTM Hub has been lost. As a result, the integration is currently inactive.</p>
  <p>To restore functionality, please navigate to the <strong>Settings</strong> section and re-initiate the registration process for the OpenCTI platform. This will re-establish the connection and allow continued use of the integrated features.</p>
  <p>If you need assistance during the process, don’t hesitate to reach out.</p>
  <p>
    <a href="${getBaseUrl()}">Access OpenCTI</a><br />
    Best,<br />
    Filigran Team<br />
  </p>
`;

const loadAdministratorsList = async (context: AuthContext) => {
  const administrators = (await findUserWithCapabilities(context, HUB_REGISTRATION_MANAGER_USER, [BYPASS, SETTINGS_SETMANAGEXTMHUB])) as AuthUser[];
  if (administrators.length > MAX_EMAIL_LIST_SIZE) {
    logApp.warn(`Administrators list too large, loading only ${MAX_EMAIL_LIST_SIZE} first administrators.`);
    return administrators.slice(0, MAX_EMAIL_LIST_SIZE);
  }

  return administrators;
};

export const sendAdministratorsLostConnectivityEmail = async (context: AuthContext, settings: BasicStoreSettings) => {
  const administrators = await loadAdministratorsList(context);
  const subject = 'Action Required: Re-register OpenCTI Platform Due to Lost Connectivity with XTM Hub';
  const html = await safeRender(OCTI_EMAIL_TEMPLATE, { settings: sanitizeSettings(settings), body: EMAIL_BODY });

  const sendMailArgs: SendMailArgs = {
    from: await smtpComputeFrom(),
    to: TO_EMAIL,
    bcc: administrators.map((administrator) => administrator.user_email),
    subject,
    html,
  };

  await sendMail(sendMailArgs, { category: 'hub-registration' });
};
