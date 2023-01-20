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
import { READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_META_RELATIONSHIPS, READ_STIX_INDICES } from '../database/utils';
import { elPaginate } from '../database/engine';
import { convertFiltersToQueryOptions } from '../utils/filtering';

// Retention manager responsible to cleanup old data
// Each API will start is retention manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('retention_manager:interval') || 60000;
const RETENTION_MANAGER_KEY = conf.get('retention_manager:lock_key') || 'retention_manager_lock';
const RETENTION_BATCH_SIZE = conf.get('retention_manager:batch_size') || 100;
const RETENTION_INDICES = [...READ_STIX_INDICES, READ_INDEX_STIX_META_OBJECTS, READ_INDEX_STIX_META_RELATIONSHIPS];
let running = false;

const executeProcessing = async (context, retentionRule) => {
  const { id, name, max_retention: maxDays, filters } = retentionRule;
  logApp.debug(`[OPENCTI] Executing retention manager rule ${name}`);
  const jsonFilters = JSON.parse(filters || '{}');
  const before = utcDate().subtract(maxDays, 'days');
  const queryOptions = await convertFiltersToQueryOptions(context, jsonFilters, { before });
  const opts = { ...queryOptions, first: RETENTION_BATCH_SIZE };
  const result = await elPaginate(context, RETENTION_MANAGER_USER, RETENTION_INDICES, opts);
  const remainingDeletions = result.pageInfo.globalCount;
  const elements = result.edges;
  logApp.debug(`[OPENCTI] Retention manager clearing ${elements.length} elements`);
  for (let index = 0; index < elements.length; index += 1) {
    const { node } = elements[index];
    const { updated_at: up } = node;
    const humanDuration = moment.duration(utcDate(up).diff(utcDate())).humanize();
    try {
      await deleteElementById(context, RETENTION_MANAGER_USER, node.internal_id, node.entity_type);
      logApp.debug(`[OPENCTI] Retention manager deleting ${node.id} after ${humanDuration}`);
    } catch (e) {
      logApp.error(`[OPENCTI] Retention manager error deleting ${node.id}`, { error: e });
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
    lock = await lockResource([RETENTION_MANAGER_KEY]);
    running = true;
    const context = executionContext('retention_manager');
    const retentionRules = await findRetentionRulesToExecute(context, RETENTION_MANAGER_USER, { connectionFormat: false });
    logApp.debug(`[OPENCTI] Retention manager execution for ${retentionRules.length} rules`);
    // Execution of retention rules
    if (retentionRules.length > 0) {
      for (let index = 0; index < retentionRules.length; index += 1) {
        const retentionRule = retentionRules[index];
        await executeProcessing(context, retentionRule);
      }
    }
  } catch (e) {
    // We dont care about failing to get the lock.
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI-MODULE] Retention manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Retention manager fail to execute', { error: e });
    }
  } finally {
    running = false;
    if (lock) await lock.unlock();
  }
};
const initRetentionManager = () => {
  let scheduler;
  return {
    start: () => {
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
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const retentionManager = initRetentionManager();

export default retentionManager;
