import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { DECAY_MANAGER_USER, executionContext } from '../utils/access';
import { findIndicatorsForDecay, updateIndicatorDecayScore } from '../modules/indicator/indicator-domain';

const INDICATOR_DECAY_MANAGER_ENABLED = booleanConf('indicator_decay_manager:enabled', true);
const INDICATOR_DECAY_MANAGER_KEY = conf.get('indicator_decay_manager:lock_key') || 'indicator_decay_manager_lock';
const SCHEDULE_TIME = conf.get('indicator_decay_manager:interval') || 60000; // 1 minute
const BATCH_SIZE = conf.get('indicator_decay_manager:batch_size') || 10000;

/**
 * Search for N (batch_size) older Indicators that requires to have the current stable score to be updated
 * based on decay_next_reaction_date.
 * Update the stable score to the next value, and revoke indicators if needed.
 */
export const indicatorDecayHandler = async () => {
  const context = executionContext('indicator_decay_manager');
  const indicatorsToUpdate = await findIndicatorsForDecay(context, DECAY_MANAGER_USER, BATCH_SIZE);
  let errorCount = 0;
  for (let i = 0; i < indicatorsToUpdate.length; i += 1) {
    try {
      const indicator = indicatorsToUpdate[i];
      await updateIndicatorDecayScore(context, DECAY_MANAGER_USER, indicator);
    } catch (e) {
      logApp.error('[OPENCTI-MODULE] Error when processing decay, skipping.', { cause: e, id: indicatorsToUpdate[i].id });
      errorCount += 1;
    }
  }
  if (errorCount > 0) {
    logApp.error('[OPENCTI-MODULE] Indicator decay manager got errors. Please have a look to previous warning.', {
      errors_count: errorCount,
      indicators_count: indicatorsToUpdate.length
    });
  } else {
    logApp.debug('[OPENCTI-MODULE] Indicator decay manager updated', { indicators_count: indicatorsToUpdate.length });
  }
};

const INDICATOR_DECAY_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'INDICATOR_DECAY_MANAGER',
  label: 'Indicator decay manager',
  executionContext: 'indicator_decay_manager',
  cronSchedulerHandler: {
    handler: indicatorDecayHandler,
    interval: SCHEDULE_TIME,
    lockKey: INDICATOR_DECAY_MANAGER_KEY,
  },
  enabledByConfig: INDICATOR_DECAY_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

registerManager(INDICATOR_DECAY_MANAGER_DEFINITION);
