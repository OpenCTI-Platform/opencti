import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import moment from 'moment';
import { lockResource } from '../database/redis';
import { findAll as findRetentionRulesToExecute } from '../domain/retentionRule';
import conf, { logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { BYPASS, ROLE_ADMINISTRATOR } from '../utils/access';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { now, utcDate } from '../utils/format';
import { READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_META_RELATIONSHIPS, READ_STIX_INDICES } from '../database/utils';
import { convertFiltersToQueryOptions } from '../domain/taxii';
import { elPaginate } from '../database/elasticSearch';

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
const RETENTION_BATCH_SIZE = conf.get('retention_manager:batch_size') || 1000;
const RETENTION_INDICES = [...READ_STIX_INDICES, READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_META_RELATIONSHIPS];

const executeProcessing = async (retentionRule) => {
  const { id, name, max_retention: maxDays, filters } = retentionRule;
  logApp.debug(`[OPENCTI] Executing retention manager rule ${name}`);
  const jsonFilters = JSON.parse(filters || '{}');
  const before = utcDate().subtract(maxDays, 'days');
  const queryOptions = convertFiltersToQueryOptions(jsonFilters, { before });
  const opts = { ...queryOptions, first: RETENTION_BATCH_SIZE };
  const result = await elPaginate(RETENTION_MANAGER_USER, RETENTION_INDICES, opts);
  const remainingDeletions = result.pageInfo.globalCount;
  const elements = result.edges;
  logApp.debug(`[OPENCTI] Retention manager clearing ${elements.length} elements`);
  for (let index = 0; index < elements.length; index += 1) {
    const { node } = elements[index];
    const { updated_at: up } = node;
    const humanDuration = moment.duration(utcDate(up).diff(utcDate())).humanize();
    logApp.debug(`[OPENCTI] Retention manager deleting ${node.id} after ${humanDuration}`);
    await deleteElementById(RETENTION_MANAGER_USER, node.internal_id, node.entity_type);
  }
  // Patch the last execution of the rule
  const patch = {
    last_execution_date: now(),
    remaining_count: remainingDeletions,
    last_deleted_count: elements.length,
  };
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
