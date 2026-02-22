import conf from '../config/conf';
import { logApp } from '../config/conf';
import { executionContext } from '../utils/access';
import { SYSTEM_USER } from '../utils/access';
import { registerWithXtmOne } from '../modules/xtm/one/xtm-one';
import type { ManagerDefinition } from './managerModule';
import { registerManager } from './managerModule';

const XTM_ONE_URL = conf.get('xtm:xtm_one_url');
const XTM_ONE_TOKEN = conf.get('xtm:xtm_one_token');
const XTM_ONE_ENABLED = !!(XTM_ONE_URL && XTM_ONE_TOKEN);
const SCHEDULE_TIME = conf.get('hub_registration_manager:interval') || 60 * 60 * 1000; // 1 hour

export const xtmOneRegistrationManager = async () => {
  const context = executionContext('xtm_one_registration_manager');
  try {
    await registerWithXtmOne(context, SYSTEM_USER);
  } catch (error: any) {
    logApp.error('[XTM One] Registration manager error', { error: error.message });
  }
};

const XTM_ONE_REGISTRATION_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'XTM_ONE_REGISTRATION_MANAGER',
  label: 'XTM One registration manager',
  executionContext: 'xtm_one_registration_manager',
  cronSchedulerHandler: {
    handler: xtmOneRegistrationManager,
    interval: SCHEDULE_TIME,
    lockKey: 'xtm_one_registration_manager_lock',
  },
  enabledByConfig: XTM_ONE_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
  warning(): boolean {
    return XTM_ONE_ENABLED && (!XTM_ONE_URL || !XTM_ONE_TOKEN);
  },
};

registerManager(XTM_ONE_REGISTRATION_MANAGER_DEFINITION);
