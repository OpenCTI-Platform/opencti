import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { DATA_SANITY_MANAGER_USER, executionContext } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';
import { findForceRunOperations, hasOperationBeenExecuted, markOperationAsExecuted, markOperationAsRunning } from '../modules/dataSanity/dataSanity-domain';
import { type SanityOperation, sanityOperationList } from '../modules/dataSanity/dataSanity-operations';

const DATA_SANITY_MANAGER_ID = 'DATA_SANITY_MANAGER';
const DATA_SANITY_MANAGER_LABEL = 'Data sanity manager';
const DATA_SANITY_MANAGER_CONTEXT = 'data_sanity_manager';

const DATA_SANITY_MANAGER_ENABLED = booleanConf('data_sanity_manager:enabled', true);
const DATA_SANITY_MANAGER_KEY = conf.get('data_sanity_manager:lock_key') || 'data_sanity_manager_lock';
const SCHEDULE_TIME = conf.get('data_sanity_manager:interval') || 600000;

/**
 * Determines if an operation should be skipped based on its execution_type and state in ElasticSearch.
 * - run_once: skip if already executed (unless force_run is set)
 */
const shouldSkipOperation = async (context: AuthContext, user: AuthUser, operation: SanityOperation): Promise<boolean> => {
  return hasOperationBeenExecuted(context, user, operation.identifier);
};

export const dataSanityForceRunHandler = async (context: AuthContext) => {
  // Run force_run operations from ElasticSearch (operations triggered on demand via the force_run flag)
  const forceRunEntities = await findForceRunOperations(context, DATA_SANITY_MANAGER_USER);
  for (const entity of forceRunEntities) {
    // Find the corresponding operation function in the registry
    const operation = sanityOperationList().find((op: SanityOperation) => op.identifier === entity.operation_name);
    if (!operation) {
      logApp.warn('[DATA_SANITY_MANAGER] Force run requested for unknown operation, skipping', { operation_name: entity.operation_name });
      continue;
    }
    const startTime = Date.now();
    try {
      logApp.info('[DATA_SANITY_MANAGER] Executing force_run data sanity operation', { operation: operation.identifier });
      await markOperationAsRunning(context, DATA_SANITY_MANAGER_USER, operation.identifier);
      const output = await operation.operationRun(context);
      const executionTimeMs = Date.now() - startTime;
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.identifier, executionTimeMs, true, '', output);
      logApp.info('[DATA_SANITY_MANAGER] Force_run data sanity operation completed successfully', { operation: operation.identifier, executionTimeMs });
    } catch (e: any) {
      const executionTimeMs = Date.now() - startTime;
      const errorMessage = e?.message || String(e);
      logApp.error('[DATA_SANITY_MANAGER] Force_run data sanity operation failed', { operation: operation.identifier, error: e });
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.identifier, executionTimeMs, false, errorMessage).catch(() => {});
    }
  }
};

export const dataSanityListHandler = async (context: AuthContext, user: AuthUser) => {
  for (const operation of sanityOperationList()) {
    const shouldSkip = await shouldSkipOperation(context, user, operation);
    if (shouldSkip) {
      logApp.debug('[DATA_SANITY_MANAGER] Data sanity operation skipped', { operation: operation.identifier, execution_type: operation.execution_type });
      continue;
    }
    const startTime = Date.now();
    try {
      logApp.info('[DATA_SANITY_MANAGER] Executing data sanity operation', { operation: operation.identifier });
      if (operation.execution_type === 'run_once') {
        const estimatedResult = await operation.dryRun(context);
        logApp.info('[DATA_SANITY_MANAGER] Estimating run_once impact before actual run', { result: estimatedResult });
      }

      await markOperationAsRunning(context, DATA_SANITY_MANAGER_USER, operation.identifier);
      const output = await operation.operationRun(context);
      const executionTimeMs = Date.now() - startTime;
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.identifier, executionTimeMs, true, '', output);
      logApp.info('[DATA_SANITY_MANAGER] Data sanity operation completed successfully', { operation: operation.identifier, executionTimeMs });
    } catch (e: any) {
      const executionTimeMs = Date.now() - startTime;
      const errorMessage = e?.message || String(e);
      logApp.error('[DATA_SANITY_MANAGER] Data sanity operation failed', { operation: operation.identifier, error: e });
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.identifier, executionTimeMs, false, errorMessage).catch(() => {});
    }
  }
};

export const dataSanityHandler = async () => {
  const context = executionContext(DATA_SANITY_MANAGER_CONTEXT);
  logApp.info('[DATA_SANITY_MANAGER] Running data sanity manager handler', { manager: DATA_SANITY_MANAGER_ID });
  await dataSanityListHandler(context, DATA_SANITY_MANAGER_USER);
  await dataSanityForceRunHandler(context);
  logApp.info('[DATA_SANITY_MANAGER] Data sanity manager handler complete', { manager: DATA_SANITY_MANAGER_ID });
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
