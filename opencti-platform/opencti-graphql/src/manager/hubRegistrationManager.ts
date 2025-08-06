import ejs from 'ejs';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, BUS_TOPICS, getBaseUrl, isFeatureEnabled, logApp } from '../config/conf';
import { BYPASS, executionContext, HUB_REGISTRATION_MANAGER_USER, SETTINGS_SETMANAGEXTMHUB } from '../utils/access';
import { XtmHubEnrollmentStatus } from '../generated/graphql';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { xtmHubClient } from '../modules/xtm/hub/xtm-hub-client';
import { findUserWithCapabilities } from '../domain/user';
import type { AuthContext, AuthUser } from '../types/user';
import { OCTI_EMAIL_TEMPLATE } from '../utils/emailTemplates/octiEmailTemplate';
import type { SendMailArgs } from '../types/smtp';
import { sendMail } from '../database/smtp';
import { updateAttribute } from '../database/middleware';
import { notify } from '../database/redis';
import { getSettings } from '../domain/settings';

const HUB_REGISTRATION_MANAGER_ENABLED = booleanConf('hub_registration_manager:enabled', true);
const HUB_REGISTRATION_MANAGER_KEY = conf.get('hub_registration_manager:lock_key') || 'hub_registration_manager_lock';
const SCHEDULE_TIME = conf.get('hub_registration_manager:interval') || 60 * 60 * 1000; // 1 hour
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

/**
 * If platform is registered, calls XTM Hub backend to check if the registration data is still valid
 * Update the settings with the result.
 */
export const hubRegistrationManager = async () => {
  const context = executionContext('hub_registration_manager');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, HUB_REGISTRATION_MANAGER_USER, ENTITY_TYPE_SETTINGS);
  if (!settings.xtm_hub_token) {
    return;
  }

  const status = await xtmHubClient.loadRegistrationStatus({ platformId: settings.id, token: settings.xtm_hub_token });
  if (status === 'active') {
    const attributeUpdates: { key: string, value: unknown[] }[] = [{
      key: 'xtm_hub_last_connectivity_check', value: [new Date()]
    }];
    if (settings.xtm_hub_enrollment_status !== XtmHubEnrollmentStatus.Enrolled) {
      attributeUpdates.push({
        key: 'xtm_hub_enrollment_status',
        value: [XtmHubEnrollmentStatus.Enrolled]
      });
    }
    await updateAttribute(
      context,
      HUB_REGISTRATION_MANAGER_USER,
      settings.id,
      ENTITY_TYPE_SETTINGS,
      attributeUpdates
    );
  } else {
    if (settings.xtm_hub_enrollment_status === XtmHubEnrollmentStatus.Enrolled) {
      await sendAdministratorsLostConnectivityEmail(context, settings);
    }

    if (settings.xtm_hub_enrollment_status !== XtmHubEnrollmentStatus.LostConnectivity) {
      await updateAttribute(
        context,
        HUB_REGISTRATION_MANAGER_USER,
        settings.id,
        ENTITY_TYPE_SETTINGS,
        [
          {
            key: 'xtm_hub_enrollment_status',
            value: [XtmHubEnrollmentStatus.LostConnectivity]
          }
        ]
      );
    }
  }

  const updatedSettings = await getSettings(context);
  await notify(BUS_TOPICS.Settings.EDIT_TOPIC, updatedSettings, HUB_REGISTRATION_MANAGER_USER);
};

const HUB_REGISTRATION_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'HUB_REGISTRATION_MANAGER',
  label: 'XTM Hub registration manager',
  executionContext: 'hub_registration_manager',
  cronSchedulerHandler: {
    handler: hubRegistrationManager,
    interval: SCHEDULE_TIME,
    lockKey: HUB_REGISTRATION_MANAGER_KEY,
  },
  enabledByConfig: HUB_REGISTRATION_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

if (isFeatureEnabled('OCTI_ENROLLMENT')) {
  registerManager(HUB_REGISTRATION_MANAGER_DEFINITION);
}
