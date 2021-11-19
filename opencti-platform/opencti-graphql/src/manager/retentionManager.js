import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import { lockResource } from '../database/redis';
import { findAll as findRetentionRulesToExecute } from '../domain/retentionRule';
import conf, { logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { deleteElement, patchAttribute } from '../database/middleware';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { now, utcDate } from '../utils/format';
import { isEmptyField, READ_DATA_INDICES_WITHOUT_INFERRED } from '../database/utils';
import { convertFiltersToQueryOptions } from '../domain/taxii';
import { elList } from '../database/elasticSearch';

// Task manager responsible to execute long manual tasks
// Each API will start is task manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('retention_manager:interval') || 10000;
const RETENTION_MANAGER_KEY = conf.get('retention_manager:lock_key') || 'retention_manager_lock';

const queryCallback = async (elements) => {
  logApp.info(`[OPENCTI] Retention manager clearing ${elements.length} elements`);
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    await deleteElement(SYSTEM_USER, element);
  }
};

const executeProcessing = async (retentionRule) => {
  const { id, name, max_retention: maxDays, filters } = retentionRule;
  logApp.info(`[OPENCTI] Executing retention manager rule ${name}`);
  if (!isEmptyField(filters)) {
    const jsonFilters = JSON.parse(filters);
    const before = utcDate().subtract(maxDays, 'days');
    const queryOptions = convertFiltersToQueryOptions(jsonFilters, { before });
    queryOptions.infinite = true;
    queryOptions.callback = queryCallback;
    await elList(SYSTEM_USER, READ_DATA_INDICES_WITHOUT_INFERRED, queryOptions);
  }
  // Patch the last execution of the rule
  const patch = { last_execution_date: now() };
  await patchAttribute(SYSTEM_USER, id, ENTITY_TYPE_RETENTION_RULE, patch);
};

const retentionHandler = async () => {
  logApp.info('[OPENCTI] Running Retention manager');
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([RETENTION_MANAGER_KEY]);
    logApp.info('[OPENCTI] Retention manager lock acquired');
    const retentionRules = await findRetentionRulesToExecute(SYSTEM_USER, { connectionFormat: false });
    logApp.info(`[OPENCTI] Retention manager execution for ${retentionRules.length} rules`);
    // Execution of retention rules
    if (retentionRules.length > 0) {
      for (let index = 0; index < retentionRules.length; index += 1) {
        const retentionRule = retentionRules[index];
        await executeProcessing(retentionRule);
      }
    }
  } catch (e) {
    // We dont care about failing to get the lock.
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI] Retention manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI] Retention manager fail to execute', { error: e });
    }
  } finally {
    logApp.info('[OPENCTI] Retention manager execution done');
    if (lock) await lock.unlock();
  }
};
const initRetentionManager = () => {
  let scheduler;
  return {
    start: () => {
      scheduler = setIntervalAsync(async () => {
        await retentionHandler();
      }, SCHEDULE_TIME);
      // Handle hot module replacement resource dispose
      if (module.hot) {
        module.hot.dispose(async () => {
          await clearIntervalAsync(scheduler);
        });
      }
    },
    shutdown: async () => {
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const retentionManager = initRetentionManager();

export default retentionManager;
