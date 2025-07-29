import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { settingsEditField } from '../domain/settings';
import { XtmHubEnrollmentStatus } from '../generated/graphql';
import { getEntityFromCache } from '../database/cache';
import type { BasicStoreSettings } from '../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { hubClient } from '../utils/hub-client';

const HUB_ENROLLMENT_MANAGER_ENABLED = booleanConf('hub_enrollment_manager:enabled', true);
const HUB_ENROLLMENT_MANAGER_KEY = conf.get('hub_enrollment_manager:lock_key') || 'hub_enrollment_manager_lock';
const SCHEDULE_TIME = conf.get('hub_enrollment_manager:interval') || 60 * 60 * 1000; // 1 hour

/**
 * If platform is enrolled, calls XTM Hub backend to check if the enrollment data is still valid
 * Update the settings with the result.
 */
export const hubEnrollmentHandler = async () => {
  const context = executionContext('hub_enrollment_manager');
  const storeSettings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  if (!storeSettings.xtm_hub_token) {
    return;
  }

  const status = await hubClient.loadEnrollmentStatus({ platformId: storeSettings.id, token: storeSettings.xtm_hub_token });
  if (status === 'active') {
    await settingsEditField(
      context,
      SYSTEM_USER,
      storeSettings.id,
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
    await settingsEditField(
      context,
      SYSTEM_USER,
      storeSettings.id,
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
