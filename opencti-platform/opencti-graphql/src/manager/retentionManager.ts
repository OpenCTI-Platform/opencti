import moment from 'moment';
import { findAll as findRetentionRulesToExecute } from '../domain/retentionRule';
import conf, { booleanConf, logApp } from '../config/conf';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { executionContext, RETENTION_MANAGER_USER } from '../utils/access';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { now, utcDate } from '../utils/format';
import { READ_STIX_INDICES } from '../database/utils';
import { elPaginate } from '../database/engine';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';
import type { ManagerDefinition } from './managerModule';
import { registerManager } from './managerModule';
import type { AuthContext } from '../types/user';
import type { RetentionRule } from '../generated/graphql';

const RETENTION_MANAGER_ENABLED = booleanConf('retention_manager:enabled', false);
// Retention manager responsible to cleanup old data
// Each API will start is retention manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('retention_manager:interval') || 60000;
const RETENTION_MANAGER_KEY = conf.get('retention_manager:lock_key') || 'retention_manager_lock';
const RETENTION_BATCH_SIZE = conf.get('retention_manager:batch_size') || 100;

const executeProcessing = async (context: AuthContext, retentionRule: RetentionRule) => {
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

const retentionHandler = async (lock: { signal: AbortSignal, extend: () => Promise<void>, unlock: () => Promise<void> }) => {
  const context = executionContext('retention_manager');
  const retentionRules = await findRetentionRulesToExecute(context, RETENTION_MANAGER_USER, { connectionFormat: false });
  logApp.debug(`[OPENCTI] Retention manager execution for ${retentionRules.length} rules`);
  // Execution of retention rules
  if (retentionRules.length > 0) {
    for (let index = 0; index < retentionRules.length; index += 1) {
      lock.signal.throwIfAborted();
      const retentionRule = retentionRules[index];
      await executeProcessing(context, retentionRule as unknown as RetentionRule);
    }
  }
};

const RETENTION_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'RETENTION_MANAGER',
  label: 'Retention manager',
  executionContext: 'retention_manager',
  cronSchedulerHandler: {
    handler: retentionHandler,
    interval: SCHEDULE_TIME,
    lockKey: RETENTION_MANAGER_KEY,
    lockInHandlerParams: true,
  },
  enabledByConfig: RETENTION_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

registerManager(RETENTION_MANAGER_DEFINITION);
