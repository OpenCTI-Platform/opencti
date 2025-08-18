import ejs from 'ejs';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { xtmHubClient } from '../modules/xtm/hub/xtm-hub-client';
import { XtmHubRegistrationStatus } from '../generated/graphql';
import { updateAttribute } from '../database/middleware';
import conf, { BUS_TOPICS, getBaseUrl, logApp } from '../config/conf';
import { findUserWithCapabilities } from './user';
import { BYPASS, HUB_REGISTRATION_MANAGER_USER, SETTINGS_SETMANAGEXTMHUB } from '../utils/access';
import { OCTI_EMAIL_TEMPLATE } from '../utils/emailTemplates/octiEmailTemplate';
import type { SendMailArgs } from '../types/smtp';
import { sendMail } from '../database/smtp';
import { getSettings } from './settings';
import { notify } from '../database/redis';

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

const sendAdministratorsLostConnectivityEmail = async (context: AuthContext, settings: BasicStoreSettings) => {
  const administrators = await loadAdministratorsList(context);
  const subject = 'Action Required: Re-register OpenCTI Platform Due to Lost Connectivity with XTM Hub';
  const html = ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body: EMAIL_BODY });

  const sendMailArgs: SendMailArgs = {
    from: `${settings.platform_title} <${settings.platform_email}>`,
    to: TO_EMAIL,
    bcc: administrators.map((administrator) => administrator.user_email),
    subject,
    html,
  };

  await sendMail(sendMailArgs, { category: 'hub-registration' });
};

export const checkXTMHubConnectivity = async (context: AuthContext, user: AuthUser, { mustSendEmail }: { mustSendEmail: boolean }) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  if (!settings.xtm_hub_token) {
    return;
  }

  const status = await xtmHubClient.loadRegistrationStatus({ platformId: settings.id, token: settings.xtm_hub_token });
  if (status === 'active') {
    const attributeUpdates: { key: string, value: unknown[] }[] = [{
      key: 'xtm_hub_last_connectivity_check', value: [new Date()]
    }];
    if (settings.xtm_hub_registration_status !== XtmHubRegistrationStatus.Registered) {
      attributeUpdates.push({
        key: 'xtm_hub_registration_status',
        value: [XtmHubRegistrationStatus.Registered]
      });
    }
    await updateAttribute(
      context,
      user,
      settings.id,
      ENTITY_TYPE_SETTINGS,
      attributeUpdates
    );
  } else {
    if (settings.xtm_hub_registration_status !== XtmHubRegistrationStatus.LostConnectivity) {
      await updateAttribute(
        context,
        user,
        settings.id,
        ENTITY_TYPE_SETTINGS,
        [
          {
            key: 'xtm_hub_registration_status',
            value: [XtmHubRegistrationStatus.LostConnectivity]
          }
        ]
      );
    }

    if (settings.xtm_hub_registration_status === XtmHubRegistrationStatus.Registered && mustSendEmail) {
      await sendAdministratorsLostConnectivityEmail(context, settings);
    }
  }

  const updatedSettings = await getSettings(context);
  await notify(BUS_TOPICS.Settings.EDIT_TOPIC, updatedSettings, HUB_REGISTRATION_MANAGER_USER);
};
