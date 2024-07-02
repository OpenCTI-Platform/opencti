import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import moment from 'moment';
import { lockResource } from '../database/redis';
import { findAll as findRetentionRulesToExecute } from '../domain/retentionRule';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { executionContext, RETENTION_MANAGER_USER } from '../utils/access';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { now, utcDate } from '../utils/format';
import { READ_STIX_INDICES } from '../database/utils';
import { elPaginate } from '../database/engine';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';

// Retention manager responsible to cleanup old data
// Each API will start is retention manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('retention_manager:interval') || 60000;
const RETENTION_MANAGER_KEY = conf.get('retention_manager:lock_key') || 'retention_manager_lock';
const RETENTION_BATCH_SIZE = conf.get('retention_manager:batch_size') || 100;
let running = false;

const executeProcessing = async (context, retentionRule) => {
  const { id, name, max_retention: maxDays, filters } = retentionRule;
  logApp.debug(`[OPENCTI] Executing retention manager rule ${name}`);
  const jsonFilters = filters ? JSON.parse(filters) : null;
  const before = utcDate().subtract(maxDays, 'days');
  const queryOptions = await convertFiltersToQueryOptions(jsonFilters, { before });
  const opts = { ...queryOptions, first: RETENTION_BATCH_SIZE };
  const result = await elPaginate(context, RETENTION_MANAGER_USER, READ_STIX_INDICES, opts);
  const remainingDeletions = result.pageInfo.globalCount;
  const elements = result.edges;
  logApp.debug(`[OPENCTI] Retention manager clearing ${elements.length} elements`);
  for (let index = 0; index < elements.length; index += 1) {
    const { node } = elements[index];
    const { updated_at: up } = node;
    const humanDuration = moment.duration(utcDate(up).diff(utcDate())).humanize();
    try {
      await deleteElementById(context, RETENTION_MANAGER_USER, node.internal_id, node.entity_type, { forceDelete: true });
      logApp.debug(`[OPENCTI] Retention manager deleting ${node.id} after ${humanDuration}`);
    } catch (e) {
      logApp.error(e, { id: node.id, manager: 'RETENTION_MANAGER' });
    }
  }
  // Patch the last execution of the rule
  const patch = {
    last_execution_date: now(),
    remaining_count: remainingDeletions,
    last_deleted_count: elements.length,
  };
  await patchAttribute(context, RETENTION_MANAGER_USER, id, ENTITY_TYPE_RETENTION_RULE, patch);
};

const retentionHandler = async () => {
  logApp.debug('[OPENCTI-MODULE] Running retention manager');
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([RETENTION_MANAGER_KEY], { retryCount: 0 });
    running = true;
    const context = executionContext('retention_manager');
    const retentionRules = await findRetentionRulesToExecute(context, RETENTION_MANAGER_USER, { connectionFormat: false });
    logApp.debug(`[OPENCTI] Retention manager execution for ${retentionRules.length} rules`);
    // Execution of retention rules
    if (retentionRules.length > 0) {
      for (let index = 0; index < retentionRules.length; index += 1) {
        lock.signal.throwIfAborted();
        const retentionRule = retentionRules[index];
        await executeProcessing(context, retentionRule);
      }
    }
  } catch (e) {
    // We dont care about failing to get the lock.
    if (e.extensions.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Retention manager already in progress by another API');
    } else {
      logApp.error(e, { manager: 'RETENTION_MANAGER' });
    }
  } finally {
    running = false;
    if (lock) await lock.unlock();
  }
};
const initRetentionManager = () => {
  let scheduler;
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Running retention manager');
      scheduler = setIntervalAsync(async () => {
        await retentionHandler();
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'RETENTION_MANAGER',
        enable: booleanConf('retention_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping retention manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const retentionManager = initRetentionManager();

export default retentionManager;
