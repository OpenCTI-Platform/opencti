var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { findIndicatorsForDecay, updateIndicatorDecayScore } from '../modules/indicator/indicator-domain';
const INDICATOR_DECAY_MANAGER_ENABLED = booleanConf('indicator_decay_manager:enabled', false);
const INDICATOR_DECAY_MANAGER_KEY = conf.get('indicator_decay_manager:lock_key') || 'indicator_decay_manager_lock';
const SCHEDULE_TIME = conf.get('indicator_decay_manager:interval') || 60000; // 1 minute
const BATCH_SIZE = conf.get('indicator_decay_manager:batch_size') || 10000;
/**
 * Search for N (batch_size) older Indicators that requires to have the current stable score to be updated
 * based on decay_next_reaction_date.
 * Update the stable score to the next value, and revoke indicators if needed.
 */
export const indicatorDecayHandler = () => __awaiter(void 0, void 0, void 0, function* () {
    const context = executionContext('indicator_decay_manager');
    const indicatorsToUpdate = yield findIndicatorsForDecay(context, SYSTEM_USER, BATCH_SIZE);
    let errorCount = 0;
    for (let i = 0; i < indicatorsToUpdate.length; i += 1) {
        try {
            const indicator = indicatorsToUpdate[i];
            yield updateIndicatorDecayScore(context, SYSTEM_USER, indicator);
        }
        catch (e) {
            logApp.warn(`[OPENCTI-MODULE] Error when processing decay for ${indicatorsToUpdate[i].id}, skipping.`);
            errorCount += 1;
        }
    }
    if (errorCount > 0) {
        logApp.error(`[OPENCTI-MODULE] Indicator decay manager got ${errorCount} error for ${indicatorsToUpdate.length} indicators. Please have a look to previous warning.`);
    }
    else {
        logApp.debug(`[OPENCTI-MODULE] Indicator decay manager updated ${indicatorsToUpdate.length} indicators`);
    }
});
const INDICATOR_DECAY_MANAGER_DEFINITION = {
    id: 'INDICATOR_DECAY_MANAGER',
    label: 'Indicator decay manager',
    executionContext: 'indicator_decay_manager',
    cronSchedulerHandler: {
        handler: indicatorDecayHandler,
        interval: SCHEDULE_TIME,
        lockKey: INDICATOR_DECAY_MANAGER_KEY,
    },
    enabledByConfig: INDICATOR_DECAY_MANAGER_ENABLED,
    enabledToStart() {
        return this.enabledByConfig;
    },
    enabled() {
        return this.enabledByConfig;
    }
};
registerManager(INDICATOR_DECAY_MANAGER_DEFINITION);
