import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { xtmHubClient } from '../modules/xtm/hub/xtm-hub-client';
import { XtmHubRegistrationStatus } from '../generated/graphql';
import { updateAttribute } from '../database/middleware';
import { BUS_TOPICS, PLATFORM_VERSION } from '../config/conf';
import { HUB_REGISTRATION_MANAGER_USER } from '../utils/access';
import { getSettings } from './settings';
import { notify } from '../database/redis';
import { utcDate } from '../utils/format';
import { sendAdministratorsLostConnectivityEmail } from '../modules/xtm/hub/xtm-hub-email';

export const checkXTMHubConnectivity = async (context: AuthContext, user: AuthUser): Promise<{
  status: XtmHubRegistrationStatus
}> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  if (!settings.xtm_hub_token) {
    return { status: XtmHubRegistrationStatus.Unregistered };
  }
  const platformInformation = { platformId: settings.id, token: settings.xtm_hub_token, platformVersion: PLATFORM_VERSION };
  const status = await xtmHubClient.refreshRegistrationStatus(platformInformation);
  const isConnectivityActive = status === 'active';
  const newRegistrationStatus: XtmHubRegistrationStatus = isConnectivityActive ? XtmHubRegistrationStatus.Registered : XtmHubRegistrationStatus.LostConnectivity;
  const attributeUpdates: { key: string, value: unknown[] }[] = [];

  const shouldUpdateRegistrationStatus = newRegistrationStatus !== settings.xtm_hub_registration_status;
  if (shouldUpdateRegistrationStatus) {
    attributeUpdates.push({ key: 'xtm_hub_registration_status', value: [newRegistrationStatus] });
  }

  const lastCheckDate = utcDate(settings.xtm_hub_last_connectivity_check);
  const are24HoursPassed = utcDate().diff(lastCheckDate, 'hours') >= 24;
  const shouldSendLostConnectivityEmail = !isConnectivityActive
    && are24HoursPassed
    && settings.xtm_hub_should_send_connectivity_email;
  if (shouldSendLostConnectivityEmail) {
    await sendAdministratorsLostConnectivityEmail(context, settings);
    attributeUpdates.push({ key: 'xtm_hub_should_send_connectivity_email', value: [false] });
  }

  if (isConnectivityActive) {
    attributeUpdates.push({ key: 'xtm_hub_last_connectivity_check', value: [new Date()] });

    const shouldAllowConnectivityLostEmailAgain = !settings.xtm_hub_should_send_connectivity_email;
    if (shouldAllowConnectivityLostEmailAgain) {
      attributeUpdates.push({ key: 'xtm_hub_should_send_connectivity_email', value: [true] });
    }
  }

  const { isReachable } = await xtmHubClient.isBackendReachable();
  attributeUpdates.push({ key: 'xtm_hub_backend_is_reachable', value: [isReachable] });

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
