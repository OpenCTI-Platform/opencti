import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext } from '../utils/access';
import { runPulseContribution, runPulseRefresh } from '../modules/xtm/pulse/pulse-domain';
import { runPulseTrendingNotifications } from '../modules/xtm/pulse/pulse-notifications';
import { redisSetPulseState } from '../modules/xtm/pulse/pulse-cache';

const PULSE_MANAGER_ENABLED = booleanConf('pulse_manager:enabled', true);
const PULSE_MANAGER_KEY = conf.get('pulse_manager:lock_key') || 'pulse_manager_lock';
const SCHEDULE_TIME = conf.get('pulse_manager:interval') || 60 * 60 * 1000; // 1 hour

const runStep = async (step: string, run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    logApp.error(`[THREAT PULSE] ${step} failed`, { cause: error, manager: 'PULSE_MANAGER' });
    await redisSetPulseState({ last_error: `${step.toLowerCase().replaceAll(' ', '_')}_failed` });
  }
};

/**
 * Hourly Threat Pulse cycle, a no-op until an administrator opts in:
 * contributes the activity of the last window (hashes and counts only), refreshes the network information of the
 * objects in scope once a day, and notifies the triggers listening to objects trending in the platform's sector.
 */
export const pulseManager = async () => {
  const context = executionContext('pulse_manager');
  await runStep('Contribution', () => runPulseContribution(context));
  await runStep('Network refresh', () => runPulseRefresh(context));
  await runStep('Trending notifications', () => runPulseTrendingNotifications(context));
};

const PULSE_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'PULSE_MANAGER',
  label: 'Threat Pulse manager',
  executionContext: 'pulse_manager',
  cronSchedulerHandler: {
    handler: pulseManager,
    interval: SCHEDULE_TIME,
    lockKey: PULSE_MANAGER_KEY,
  },
  enabledByConfig: PULSE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};
registerManager(PULSE_MANAGER_DEFINITION);
