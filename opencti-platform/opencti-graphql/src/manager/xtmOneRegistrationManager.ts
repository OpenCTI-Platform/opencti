import conf, { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { registerWithXtmOne } from '../modules/xtm/one/xtm-one';
import type { ManagerDefinition } from './managerModule';
import { registerManager } from './managerModule';

const XTM_ONE_URL = conf.get('xtm:xtm_one_url');
const XTM_ONE_TOKEN = conf.get('xtm:xtm_one_token');
const XTM_ONE_ENABLED = !!(XTM_ONE_URL && XTM_ONE_TOKEN);
const SCHEDULE_TIME = 5 * 60 * 1000; // 5 minutes
const BOOT_DELAY = 30_000; // 30 seconds — let the platform finish init

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
    return false;
  },
};

registerManager(XTM_ONE_REGISTRATION_MANAGER_DEFINITION);

// Fire once at boot so the platform appears in XTM One immediately
// instead of waiting for the first interval tick.
if (XTM_ONE_ENABLED) {
  setTimeout(() => {
    xtmOneRegistrationManager().catch((err: any) => {
      logApp.warn('[XTM One] Boot registration failed, will retry on next tick', { error: err.message });
    });
  }, BOOT_DELAY);
}
