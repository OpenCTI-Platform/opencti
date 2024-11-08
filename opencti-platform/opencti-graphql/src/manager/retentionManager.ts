import moment, { type Moment } from 'moment';
import { Promise as BluePromise } from 'bluebird';
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
import type { FileEdge, RetentionRule } from '../generated/graphql';
import { RetentionRuleScope, RetentionUnit } from '../generated/graphql';
import { deleteFile } from '../database/file-storage';
import { DELETABLE_FILE_STATUSES, paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { organizationDelete } from '../modules/organization/organization-domain';
import type { BasicStoreCommonEdge, StoreObject } from '../types/store';
import { ALREADY_DELETED_ERROR } from '../config/errors';

const RETENTION_MANAGER_ENABLED = booleanConf('retention_manager:enabled', false);
const RETENTION_MANAGER_START_ENABLED = booleanConf('retention_manager:enabled', true);
// Retention manager responsible to cleanup old data
// Each API will start is retention manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('retention_manager:interval') || 30000;
const RETENTION_MANAGER_KEY = conf.get('retention_manager:lock_key') || 'retention_manager_lock';
const RETENTION_BATCH_SIZE = conf.get('retention_manager:batch_size') || 1500;
const RETENTION_MAX_CONCURRENCY = conf.get('retention_manager:max_deletion_concurrency') || 10;
export const RETENTION_SCOPE_VALUES = Object.values(RetentionRuleScope);
export const RETENTION_UNIT_VALUES = Object.values(RetentionUnit);

export const deleteElement = async (context: AuthContext, scope: string, nodeId: string, nodeEntityType?: string) => {
  if (scope === 'knowledge') {
    if (nodeEntityType === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
      // call organizationDelete which will ensure protections (for platform organization & members)
      await organizationDelete(context, RETENTION_MANAGER_USER, nodeId);
    } else {
      await deleteElementById(context, RETENTION_MANAGER_USER, nodeId, nodeEntityType, { forceDelete: true });
    }
  } else if (scope === 'file' || scope === 'workbench') {
    await deleteFile(context, RETENTION_MANAGER_USER, nodeId);
  } else {
    throw Error(`[Retention manager] Scope ${scope} not existing for Retention Rule.`);
  }
};

export const getElementsToDelete = async (context: AuthContext, scope: string, before: Moment, filters?: string) => {
  let result;
  if (scope === 'knowledge') {
    const jsonFilters = filters ? JSON.parse(filters) : null;
    const queryOptions = await convertFiltersToQueryOptions(jsonFilters, { before });
    result = await elPaginate(context, RETENTION_MANAGER_USER, READ_STIX_INDICES, { ...queryOptions, first: RETENTION_BATCH_SIZE });
  } else if (scope === 'file') {
    result = await paginatedForPathWithEnrichment(context, RETENTION_MANAGER_USER, 'import/global', undefined, { first: RETENTION_BATCH_SIZE, notModifiedSince: before.toISOString() });
  } else if (scope === 'workbench') {
    result = await paginatedForPathWithEnrichment(context, RETENTION_MANAGER_USER, 'import/pending', undefined, { first: RETENTION_BATCH_SIZE, notModifiedSince: before.toISOString() });
  } else {
    throw Error(`[Retention manager] Scope ${scope} not existing for Retention Rule.`);
  }
  if (scope === 'file' || scope === 'workbench') { // don't delete progress files or files with works in progress
    result.edges = result.edges.filter((e: FileEdge) => DELETABLE_FILE_STATUSES.includes(e.node.uploadStatus)
        && (e.node.works ?? []).every((work) => !work || DELETABLE_FILE_STATUSES.includes(work?.status)));
  }
  return result;
};

const executeProcessing = async (context: AuthContext, retentionRule: RetentionRule) => {
  const { id, name, max_retention: maxNumber, retention_unit: unit, filters, scope } = retentionRule;
  logApp.debug(`[OPENCTI] Executing retention manager rule ${name}`);
  const before = utcDate().subtract(maxNumber, unit ?? 'days');
  const result = await getElementsToDelete(context, scope, before, filters);
  const remainingDeletions = result.pageInfo.globalCount;
  const elements = result.edges;
  if (elements.length > 0) {
    logApp.debug(`[OPENCTI] Retention manager clearing ${elements.length} elements`);
    const start = new Date().getTime();
    const deleteFn = async (element: BasicStoreCommonEdge<StoreObject>) => {
      const { node } = element;
      const { updated_at: up } = node;
      try {
        const humanDuration = moment.duration(utcDate(up).diff(utcDate())).humanize();
        await deleteElement(context, scope, scope === 'knowledge' ? node.internal_id : node.id, node.entity_type);
        logApp.debug(`[OPENCTI] Retention manager deleting ${node.id} after ${humanDuration}`);
      } catch (err: any) {
        // Only log the error if not an already deleted message (that can happen though concurrency deletion)
        if (err?.extensions?.code !== ALREADY_DELETED_ERROR) {
          logApp.error(err, { id: node.id, manager: 'RETENTION_MANAGER' });
        }
      }
    };
    await BluePromise.map(elements, deleteFn, { concurrency: RETENTION_MAX_CONCURRENCY });
    logApp.debug(`[OPENCTI] Retention manager deleted ${elements.length} in ${new Date().getTime() - start} ms`);
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
    dynamicSchedule: true
  },
  enabledByConfig: RETENTION_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return RETENTION_MANAGER_START_ENABLED;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

registerManager(RETENTION_MANAGER_DEFINITION);
