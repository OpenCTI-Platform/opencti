import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { DATA_SANITY_MANAGER_USER, executionContext } from '../utils/access';
import type { AuthContext } from '../types/user';
import {
  findDataSanityByOperationName,
  findForceRunOperations,
  hasOperationBeenExecuted,
  markOperationAsExecuted,
  registerOnDemandOperations,
} from '../modules/dataSanity/dataSanity-domain';
import { sanityOperationList } from '../modules/dataSanity/dataSanity-configuration';
import type { SanityOperation } from '../modules/dataSanity/dataSanity-types';

const DATA_SANITY_MANAGER_ID = 'DATA_SANITY_MANAGER';
const DATA_SANITY_MANAGER_LABEL = 'Data sanity manager';
const DATA_SANITY_MANAGER_CONTEXT = 'data_sanity_manager';

const DATA_SANITY_MANAGER_ENABLED = booleanConf('data_sanity_manager:enabled', true);
const DATA_SANITY_MANAGER_KEY = conf.get('data_sanity_manager:lock_key') || 'data_sanity_manager_lock';
const SCHEDULE_TIME = conf.get('data_sanity_manager:interval') || 14400000; // 4 hours

/**
 * Determines if an operation should be skipped based on its execution_type and state in ElasticSearch.
 * - run_once: skip if already executed (unless force_run is set)
 * - on_demand: skip unless force_run is set in the DataSanity entity
 * - periodic: never skip
 */
const shouldSkipOperation = async (context: AuthContext, operation: SanityOperation): Promise<boolean> => {
  switch (operation.execution_type) {
    case 'periodic':
      return false; // always run
    case 'run_once': {
      return await hasOperationBeenExecuted(context, operation.name);
    }
    case 'on_demand': {
      const entity = await findDataSanityByOperationName(context, operation.name);
      // Only run if entity exists and force_run is true
      return !entity?.force_run;
    }
    default:
      return false;
  }
};

export const dataSanityForceRunHandler = async (context: AuthContext) => {
  // Run force_run operations from ElasticSearch (operations triggered on demand via the force_run flag)
  const forceRunEntities = await findForceRunOperations(context, DATA_SANITY_MANAGER_USER);
  const alreadyExecutedInThisRun = sanityOperationList().map((op) => op.name);
  for (const entity of forceRunEntities) {
    // Skip if already handled in the SANITY_OPERATIONS loop above
    if (alreadyExecutedInThisRun.includes(entity.operation_name)) {
      continue;
    }
    // Find the corresponding operation function in the registry
    const operation = sanityOperationList().find((op) => op.name === entity.operation_name);
    if (!operation) {
      logApp.warn('[OPENCTI-MODULE] Force run requested for unknown operation, skipping', { operation_name: entity.operation_name });
      continue;
    }
    const startTime = Date.now();
    try {
      logApp.info('[OPENCTI-MODULE] Executing force_run data sanity operation', { operation: operation.name });
      await operation.operationRun(context);
      const executionTimeMs = Date.now() - startTime;
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.name, executionTimeMs);
      logApp.info('[OPENCTI-MODULE] Force_run data sanity operation completed successfully', { operation: operation.name, executionTimeMs });
    } catch (e: any) {
      const executionTimeMs = Date.now() - startTime;
      const failureMessage = e?.message || String(e);
      logApp.error('[OPENCTI-MODULE] Force_run data sanity operation failed', { operation: operation.name, error: e });
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.name, executionTimeMs, failureMessage).catch(() => {});
    }
  }
};

export const dataSanityListHandler = async (context: AuthContext) => {
  for (const operation of sanityOperationList()) {
    const shouldSkip = await shouldSkipOperation(context, operation);
    if (shouldSkip) {
      logApp.debug('[OPENCTI-MODULE] Data sanity operation skipped', { operation: operation.name, execution_type: operation.execution_type });
      continue;
    }
    const startTime = Date.now();
    try {
      logApp.info('[OPENCTI-MODULE] Executing data sanity operation', { operation: operation.name });
      if (operation.execution_type === 'run_once') {
        const estimatedResult = await operation.dryRun(context);
        logApp.info('[OPENCTI-MODULE] Estimating run_once impact before actual run', { result: estimatedResult });
      }

      await operation.operationRun(context);
      const executionTimeMs = Date.now() - startTime;
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.name, executionTimeMs);
      logApp.info('[OPENCTI-MODULE] Data sanity operation completed successfully', { operation: operation.name, executionTimeMs });
    } catch (e: any) {
      const executionTimeMs = Date.now() - startTime;
      const failureMessage = e?.message || String(e);
      logApp.error('[OPENCTI-MODULE] Data sanity operation failed', { operation: operation.name, error: e });
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.name, executionTimeMs, failureMessage).catch(() => {});
    }
  }
};

export const dataSanityHandler = async () => {
  const context = executionContext(DATA_SANITY_MANAGER_CONTEXT);
  logApp.debug('[OPENCTI-MODULE] Running data sanity manager handler', { manager: DATA_SANITY_MANAGER_ID });
  // Register on_demand operations in ElasticSearch so they can be triggered via force_run later
  await registerOnDemandOperations(context, DATA_SANITY_MANAGER_USER);
  await dataSanityListHandler(context);
  await dataSanityForceRunHandler(context);
  logApp.debug('[OPENCTI-MODULE] Data sanity manager handler complete', { manager: DATA_SANITY_MANAGER_ID });
};

const DATA_SANITY_MANAGER_DEFINITION: ManagerDefinition = {
  id: DATA_SANITY_MANAGER_ID,
  label: DATA_SANITY_MANAGER_LABEL,
  executionContext: DATA_SANITY_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: dataSanityHandler,
    interval: SCHEDULE_TIME,
    lockKey: DATA_SANITY_MANAGER_KEY,
  },
  enabledByConfig: DATA_SANITY_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(DATA_SANITY_MANAGER_DEFINITION);
