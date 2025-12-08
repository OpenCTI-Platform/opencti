import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { xtmHubClient } from '../modules/xtm/hub/xtm-hub-client';
import { type AutoRegisterInput, XtmHubRegistrationStatus } from '../generated/graphql';
import { updateAttribute } from '../database/middleware';
import { booleanConf, BUS_TOPICS, logApp, PLATFORM_VERSION } from '../config/conf';
import { HUB_REGISTRATION_MANAGER_USER } from '../utils/access';
import { getSettings, settingsEditField } from './settings';
import { notify } from '../database/redis';
import { utcDate } from '../utils/format';
import { sendAdministratorsLostConnectivityEmail } from '../modules/xtm/hub/xtm-hub-email';
import { getEnterpriseEditionInfoFromPem } from '../modules/settings/licensing';

interface AttributeUpdate {
  key: keyof BasicStoreSettings
  value: unknown[]
}

export const checkXTMHubConnectivity = async (context: AuthContext, user: AuthUser): Promise<{
  status: XtmHubRegistrationStatus
}> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  await checkHubIfBackendIsReachable(context, user, settings);
  if (!settings.xtm_hub_token) {
    return { status: XtmHubRegistrationStatus.Unregistered };
  }
  const platformInformation = { platformId: settings.id, token: settings.xtm_hub_token, platformVersion: PLATFORM_VERSION };
  const status = await xtmHubClient.refreshRegistrationStatus(platformInformation);
  if (status === 'not_found') {
    logApp.warn('[XTMH] Platform was not found on XTM Hub');
    await resetRegistration(context, user, settings);
    return { status: XtmHubRegistrationStatus.Unregistered };
  }

  const isConnectivityActive = status === 'active';
  const newRegistrationStatus: XtmHubRegistrationStatus = isConnectivityActive ? XtmHubRegistrationStatus.Registered : XtmHubRegistrationStatus.LostConnectivity;
  const attributeUpdates: AttributeUpdate[] = [];

  const shouldUpdateRegistrationStatus = newRegistrationStatus !== settings.xtm_hub_registration_status;
  if (shouldUpdateRegistrationStatus) {
    attributeUpdates.push({ key: 'xtm_hub_registration_status', value: [newRegistrationStatus] });
  }

  const emailAttributeUpdates = await handleLostConnectivityEmail(context, settings, isConnectivityActive);
  attributeUpdates.push(...emailAttributeUpdates);

  if (isConnectivityActive) {
    attributeUpdates.push({ key: 'xtm_hub_last_connectivity_check', value: [new Date()] });
  }

  if (attributeUpdates.length === 0) {
    return { status: newRegistrationStatus };
  }
  await updateAttribute(
    context,
    user,
    settings.id,
    ENTITY_TYPE_SETTINGS,
    attributeUpdates
  );

  const updatedSettings = await getSettings(context);
  await notify(BUS_TOPICS.Settings.EDIT_TOPIC, updatedSettings, HUB_REGISTRATION_MANAGER_USER);

  return { status: newRegistrationStatus };
};

export const autoRegisterOpenCTI = async (context: AuthContext, user: AuthUser, input: AutoRegisterInput): Promise<{ success: boolean; } > => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);

  const licenseInfo = getEnterpriseEditionInfoFromPem(settings.internal_id, settings.enterprise_license);

  if (!input.platform_token) {
    return { success: false };
  }
  const response = await xtmHubClient.autoRegister(
    {
      platformId: settings.id,
      platformToken: input.platform_token,
      platformUrl: settings.platform_url,
      platformTitle: settings.platform_title ?? ''
    },
    licenseInfo.license_type
  );
  if (!response.success) {
    return { success: false };
  }
  await settingsEditField(
    context,
    HUB_REGISTRATION_MANAGER_USER,
    settings.id,
    [
      { key: 'xtm_hub_token', value: [input.platform_token] },
      { key: 'xtm_hub_registration_status', value: ['registered'] }
    ]
  );
  return { success: true };
};

const resetRegistration = async (context: AuthContext, user: AuthUser, settings: BasicStoreSettings) => {
  const attributeUpdates: AttributeUpdate[] = [
    {
      key: 'xtm_hub_token',
      value: []
    },
    {
      key: 'xtm_hub_registration_status',
      value: [XtmHubRegistrationStatus.Unregistered]
    },
    {
      key: 'xtm_hub_registration_user_id',
      value: []
    },
    {
      key: 'xtm_hub_registration_user_name',
      value: []
    },
    {
      key: 'xtm_hub_registration_date',
      value: []
    },
    {
      key: 'xtm_hub_last_connectivity_check',
      value: []
    }
  ];

  await updateAttribute(
    context,
    user,
    settings.id,
    ENTITY_TYPE_SETTINGS,
    attributeUpdates
  );

  const updatedSettings = await getSettings(context);
  await notify(BUS_TOPICS.Settings.EDIT_TOPIC, updatedSettings, HUB_REGISTRATION_MANAGER_USER);
};

const checkHubIfBackendIsReachable = async (context: AuthContext, user: AuthUser, settings: BasicStoreSettings) => {
  const { isReachable } = await xtmHubClient.isBackendReachable();

  await updateAttribute(
    context,
    user,
    settings.id,
    ENTITY_TYPE_SETTINGS,
    [{ key: 'xtm_hub_backend_is_reachable', value: [isReachable] }]
  );

  if (!isReachable) {
    logApp.warn('[XTMH] Backend is unreachable');
  }

  const updatedSettings = await getSettings(context);
  await notify(BUS_TOPICS.Settings.EDIT_TOPIC, updatedSettings, HUB_REGISTRATION_MANAGER_USER);
};

const handleLostConnectivityEmail = async (context: AuthContext, settings: BasicStoreSettings, isConnectivityActive: boolean): Promise<AttributeUpdate[]> => {
  const lastCheckDate = utcDate(settings.xtm_hub_last_connectivity_check);
  const are24HoursPassed = utcDate().diff(lastCheckDate, 'hours') >= 24;
  const isEmailEnabled = booleanConf('xtm:xtmhub_connectivity_email_enabled', true);
  const shouldSendLostConnectivityEmail = !isConnectivityActive
    && are24HoursPassed
    && settings.xtm_hub_should_send_connectivity_email
    && isEmailEnabled;
  const attributeUpdates: AttributeUpdate[] = [];
  if (shouldSendLostConnectivityEmail) {
    await sendAdministratorsLostConnectivityEmail(context, settings);
    attributeUpdates.push({ key: 'xtm_hub_should_send_connectivity_email', value: [false] });
  }

  const shouldAllowConnectivityLostEmailAgain = isConnectivityActive && !settings.xtm_hub_should_send_connectivity_email;
  if (shouldAllowConnectivityLostEmailAgain) {
    attributeUpdates.push({ key: 'xtm_hub_should_send_connectivity_email', value: [true] });
  }

  return attributeUpdates;
};