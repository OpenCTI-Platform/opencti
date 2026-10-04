import { type ManagerDefinition, registerManager } from './managerModule';
import { logApp } from '../config/conf';
import { isEnterpriseEdition } from '../enterprise-edition/ee';
import { executionContext, HUNT_MANAGER_USER } from '../utils/access';
import { HUNT_CONFIG } from '../modules/hunt/hunt-utils';
import { runHuntAutomation } from '../modules/hunt/hunt-automation';

const HUNT_MANAGER_ID = 'HUNT_MANAGER';
const HUNT_MANAGER_LABEL = 'Hunt manager';
const HUNT_MANAGER_CONTEXT = 'hunt_manager';

/**
 * Every tick: run lifecycle (timeouts, retries, deferred dispatch, playbook continuations, retention) for every edition,
 * then the autonomous hunts (cron schedules, PIR activation, standing hunts on stream events) with Enterprise Edition.
 */
export const huntManagerHandler = async () => {
  const context = executionContext(HUNT_MANAGER_CONTEXT, HUNT_MANAGER_USER);
  const isEnterprise = await isEnterpriseEdition(context);
  const report = await runHuntAutomation(context, isEnterprise);
  const activity = Object.values(report).reduce((sum, value) => sum + value, 0);
  if (activity > 0) {
    logApp.info('[OPENCTI-MODULE] Hunt manager tick', { manager: HUNT_MANAGER_ID, ...report });
  }
};

const HUNT_MANAGER_DEFINITION: ManagerDefinition = {
  id: HUNT_MANAGER_ID,
  label: HUNT_MANAGER_LABEL,
  executionContext: HUNT_MANAGER_CONTEXT,
  enabledByConfig: HUNT_CONFIG.enabled,
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  cronSchedulerHandler: {
    handler: huntManagerHandler,
    interval: HUNT_CONFIG.interval,
    lockKey: HUNT_CONFIG.lockKey,
  },
};

registerManager(HUNT_MANAGER_DEFINITION);
