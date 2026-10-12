import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext } from '../utils/access';
import { isPulseRefreshDeferred, runPulseContribution, runPulsePendingCleanup, runPulsePreview, runPulseRefresh } from '../modules/xtm/pulse/pulse-domain';
import { runPulseTrendingNotifications } from '../modules/xtm/pulse/pulse-notifications';
import { type PulseOperationalState, redisGetPulseState, redisSetPulseState } from '../modules/xtm/pulse/pulse-cache';

const PULSE_MANAGER_ENABLED = booleanConf('pulse_manager:enabled', true);
const PULSE_MANAGER_KEY = conf.get('pulse_manager:lock_key') || 'pulse_manager_lock';
const SCHEDULE_TIME = conf.get('pulse_manager:interval') || 60 * 60 * 1000; // 1 hour

// A step that throws leaves its own code ("network_refresh_failed", ...), so that Settings names the operation that
// failed, and clears it once it succeeds again.
const pulseStepErrorCode = (step: string) => `${step.toLowerCase().replaceAll(' ', '_')}_failed`;

/** Runs one step of the cycle; whether it succeeded. A step still `waiting` to run again keeps the code it left. */
const runStep = async (step: string, run: () => Promise<unknown>, waiting?: (state: PulseOperationalState) => boolean): Promise<boolean> => {
  const errorCode = pulseStepErrorCode(step);
  try {
    await run();
    const state = await redisGetPulseState();
    if (state.last_error === errorCode && !waiting?.(state)) {
      await redisSetPulseState({ last_error: undefined });
    }
    return true;
  } catch (error) {
    logApp.error(`[THREAT PULSE] ${step} failed`, { cause: error, manager: 'PULSE_MANAGER' });
    await redisSetPulseState({ last_error: errorCode });
    return false;
  }
};

/**
 * Hourly Threat Pulse cycle of a platform registered on XTM Hub.
 * First, registered or not, it replays a cleanup of the community data that failed (unregistration, purge, lapse):
 * while it fails, the cycle stops there, as the data the later steps write would be removed by its next success.
 * In preview (the default), it only downloads the daily digest and matches it locally, once a day: nothing leaves.
 * Contributing, it sends the activity of the last window (hashes and counts only), refreshes the network information
 * of the objects in scope once a day, and notifies the triggers listening to objects trending in the platform's sector.
 * A network refresh XTM Hub rate limited resumes from its checkpoint at the instant XTM Hub gave, not before.
 * The preview step runs after the reads, so a contribution XTM Hub no longer accepts falls back to it in the same cycle.
 */
export const pulseManager = async () => {
  const context = executionContext('pulse_manager');
  if (!(await runStep('Cleanup', () => runPulsePendingCleanup()))) return;
  await runStep('Contribution', () => runPulseContribution(context));
  // Until the instant XTM Hub gave, Settings still shows the failure of the network refresh.
  await runStep('Network refresh', () => runPulseRefresh(context), (state) => isPulseRefreshDeferred(state, Date.now()));
  await runStep('Trending notifications', () => runPulseTrendingNotifications(context));
  await runStep('Preview refresh', () => runPulsePreview(context));
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
