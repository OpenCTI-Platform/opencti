import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf } from '../config/conf';
import { executionContext, HUB_REGISTRATION_MANAGER_USER } from '../utils/access';
import { checkXTMHubConnectivity } from '../domain/xtm-hub';

const HUB_REGISTRATION_MANAGER_ENABLED = booleanConf('hub_registration_manager:enabled', true);
const HUB_REGISTRATION_MANAGER_KEY = conf.get('hub_registration_manager:lock_key') || 'hub_registration_manager_lock';
const SCHEDULE_TIME = conf.get('hub_registration_manager:interval') || 60 * 60 * 1000; // 1 hour

/**
 * If platform is registered, calls XTM Hub backend to check if the registration data is still valid
 * Update the settings with the result.
 */
export const hubRegistrationManager = async () => {
  const context = executionContext('hub_registration_manager');
  await checkXTMHubConnectivity(context, HUB_REGISTRATION_MANAGER_USER);
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

registerManager(HUB_REGISTRATION_MANAGER_DEFINITION);
