import ejs from 'ejs';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { BYPASS, executionContext, SETTINGS_SETMANAGEXTMHUB, SYSTEM_USER } from '../utils/access';
import { settingsEditField } from '../domain/settings';
import { XtmHubEnrollmentStatus } from '../generated/graphql';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { hubClient } from '../utils/hub-client';
import type { SendMailArgs } from '../types/smtp';
import { sendMail } from '../database/smtp';
import { OCTI_EMAIL_TEMPLATE } from '../utils/emailTemplates/octiEmailTemplate';
import type { AuthContext, AuthUser } from '../types/user';
import { findUserWithCapabilities } from '../domain/user';

const HUB_ENROLLMENT_MANAGER_ENABLED = booleanConf('hub_enrollment_manager:enabled', true);
const HUB_ENROLLMENT_MANAGER_KEY = conf.get('hub_enrollment_manager:lock_key') || 'hub_enrollment_manager_lock';
const SCHEDULE_TIME = conf.get('hub_enrollment_manager:interval') || 60 * 60 * 1000; // 1 hour
const MAX_ENROLLMENT_LIST_SIZE = conf.get('app:enrollment:max_list_size') || 500;
const TO_EMAIL = conf.get('app:enrollment:to_email') || 'no-reply@filigran.io';

const EMAIL_BODY = `
  <h2>Hi,</h2>
  
  <p>We wanted to inform you that the connectivity between OCTI and the XTM Hub has been lost. As a result, the integration is currently inactive.</p>
  <p>To restore functionality, please navigate to the <strong>Settings</strong> section and re-initiate the registration process for the OCTI instance. This will re-establish the connection and allow continued use of the integrated features.</p>
  <p>If you need assistance during the process, don’t hesitate to reach out.</p>
  <p>
    Best,<br />
    Filigran Team<br />
  </p>
`;

const sendAdministratorsEmail = async (context: AuthContext, settings: BasicStoreSettings) => {
  const administrators = (await findUserWithCapabilities(context, SYSTEM_USER, [BYPASS, SETTINGS_SETMANAGEXTMHUB])) as AuthUser[];
  if (administrators.length > MAX_ENROLLMENT_LIST_SIZE) {
    logApp.error(`You cannot have more than ${MAX_ENROLLMENT_LIST_SIZE} e-mail addresses`);
    return;
  }

  const subject = 'Action Required: Re-enroll OpenCTI Platform Due to Lost Connectivity with XTM Hub';
  const html = ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body: EMAIL_BODY });

  const sendMailArgs: SendMailArgs = {
    from: `${settings.platform_title} <${settings.platform_email}>`,
    to: TO_EMAIL,
    bcc: administrators.map((administrator) => administrator.user_email),
    subject,
    html,
  };

  await sendMail(sendMailArgs, { category: 'enrollment' });
};

/**
 * If platform is enrolled, calls XTM Hub backend to check if the enrollment data is still valid
 * Update the settings with the result.
 */
export const hubEnrollmentHandler = async () => {
  const context = executionContext('hub_enrollment_manager');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  if (!settings.xtm_hub_token) {
    return;
  }

  const status = await hubClient.loadEnrollmentStatus({ platformId: settings.id, token: settings.xtm_hub_token });
  if (status === 'active') {
    await settingsEditField(
      context,
      SYSTEM_USER,
      settings.id,
      [
        {
          key: 'xtm_hub_last_connectivity_check', value: [new Date()]
        },
        {
          key: 'xtm_hub_enrollment_status',
          value: [XtmHubEnrollmentStatus.Enrolled]
        }
      ]
    );
  } else {
    if (settings.xtm_hub_enrollment_status === XtmHubEnrollmentStatus.Enrolled) {
      await sendAdministratorsEmail(context, settings);
    }

    await settingsEditField(
      context,
      SYSTEM_USER,
      settings.id,
      [
        {
          key: 'xtm_hub_enrollment_status',
          value: [XtmHubEnrollmentStatus.LostConnectivity]
        }
      ]
    );
  }
};

const HUB_ENROLLMENT_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'HUB_ENROLLMENT_MANAGER',
  label: 'XTM Hub enrollment manager',
  executionContext: 'hub_enrollment_manager',
  cronSchedulerHandler: {
    handler: hubEnrollmentHandler,
    interval: SCHEDULE_TIME,
    lockKey: HUB_ENROLLMENT_MANAGER_KEY,
  },
  enabledByConfig: HUB_ENROLLMENT_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

registerManager(HUB_ENROLLMENT_MANAGER_DEFINITION);
