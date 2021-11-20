import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import moment from 'moment';
import { lockResource } from '../database/redis';
import { findAll as findRetentionRulesToExecute } from '../domain/retentionRule';
import conf, { logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { deleteElement, patchAttribute } from '../database/middleware';
import { BYPASS, ROLE_ADMINISTRATOR } from '../utils/access';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { now, utcDate } from '../utils/format';
import { isEmptyField, READ_DATA_INDICES_WITHOUT_INFERRED } from '../database/utils';
import { convertFiltersToQueryOptions } from '../domain/taxii';
import { elList } from '../database/elasticSearch';

const RETENTION_MANAGER_USER_UUID = '82ed2c6c-eb27-498e-b904-4f2abc04e05f';
export const RETENTION_MANAGER_USER = {
  id: RETENTION_MANAGER_USER_UUID,
  internal_id: RETENTION_MANAGER_USER_UUID,
  name: 'RETENTION MANAGER',
  user_email: 'RETENTION MANAGER',
  origin: {},
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
};

// Retention manager responsible to cleanup old data
// Each API will start is retention manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('retention_manager:interval') || 60000;
const RETENTION_MANAGER_KEY = conf.get('retention_manager:lock_key') || 'retention_manager_lock';

const queryCallback = async (elements) => {
  logApp.debug(`[OPENCTI] Retention manager clearing ${elements.length} elements`);
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const { updated_at: up } = element;
    const humanDuration = moment.duration(utcDate(up).diff(utcDate())).humanize();
    logApp.info(`[OPENCTI] Retention manager deleting ${element.name}/${element.id} after ${humanDuration}`);
    await deleteElement(RETENTION_MANAGER_USER, element);
  }
};

const executeProcessing = async (retentionRule) => {
  const { id, name, max_retention: maxDays, filters } = retentionRule;
  logApp.debug(`[OPENCTI] Executing retention manager rule ${name}`);
  if (!isEmptyField(filters)) {
    const jsonFilters = JSON.parse(filters);
    const before = utcDate().subtract(maxDays, 'days');
    const queryOptions = convertFiltersToQueryOptions(jsonFilters, { before });
    queryOptions.callback = queryCallback;
    await elList(RETENTION_MANAGER_USER, READ_DATA_INDICES_WITHOUT_INFERRED, queryOptions);
  }
  // Patch the last execution of the rule
  const patch = { last_execution_date: now() };
  await patchAttribute(RETENTION_MANAGER_USER, id, ENTITY_TYPE_RETENTION_RULE, patch);
};

const retentionHandler = async () => {
  logApp.debug('[OPENCTI] Running Retention manager');
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([RETENTION_MANAGER_KEY]);
    logApp.debug('[OPENCTI] Retention manager lock acquired');
    const retentionRules = await findRetentionRulesToExecute(RETENTION_MANAGER_USER, { connectionFormat: false });
    logApp.debug(`[OPENCTI] Retention manager execution for ${retentionRules.length} rules`);
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
