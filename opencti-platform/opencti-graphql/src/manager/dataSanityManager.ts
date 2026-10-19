import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { DATA_SANITY_MANAGER_USER, executionContext } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';
import { findForceRunOperations, getOperationSkipReason, getRunningLockSkipReason, markOperationAsExecuted, markOperationAsRunning } from '../modules/dataSanity/dataSanity-domain';
import { type SanityOperation, sanityOperationList } from '../modules/dataSanity/dataSanity-operations';

const DATA_SANITY_MANAGER_ID = 'DATA_SANITY_MANAGER';
const DATA_SANITY_MANAGER_CONTEXT = 'data_sanity_manager';

const DATA_SANITY_MANAGER_ENABLED = booleanConf('data_sanity_manager:enabled', true);
const DATA_SANITY_MANAGER_KEY = conf.get('data_sanity_manager:lock_key') || 'data_sanity_manager_lock';
const SCHEDULE_TIME = conf.get('data_sanity_manager:interval') || 600000;

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
    // Never start a concurrent execution: a force_run request must not bypass an active running lock
    const skipReason = getRunningLockSkipReason(entity);
    if (skipReason) {
      logApp.info('[DATA_SANITY_MANAGER] Force_run data sanity operation skipped', { operation: operation.identifier, reason: skipReason });
      continue;
    }
    const startTime = Date.now();
    let runError: any;
    let output;
    try {
      logApp.info('[DATA_SANITY_MANAGER] Executing force_run data sanity operation', { operation: operation.identifier });
      await markOperationAsRunning(context, DATA_SANITY_MANAGER_USER, operation.identifier);
      output = await operation.operationRun(context);
    } catch (e: any) {
      runError = e;
      logApp.warn('[DATA_SANITY_MANAGER] Force_run data sanity operation failed', { operation: operation.identifier, cause: e });
    }
    const executionTimeMs = Date.now() - startTime;
    try {
      const runMessage = runError ? (runError?.message || String(runError)) : '';
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.identifier, executionTimeMs, !runError, runMessage, output);
      if (!runError) {
        logApp.info('[DATA_SANITY_MANAGER] Force_run data sanity operation completed successfully', { operation: operation.identifier, executionTimeMs });
      }
    } catch (e: any) {
      // The result could not be written: the operation stays flagged as running and every
      // later pass skips it over the running lock. Needs a human.
      logApp.error('[DATA_SANITY_MANAGER] Force_run data sanity operation result could not be recorded', { operation: operation.identifier, cause: e });
    }
  }
};

export const dataSanityListHandler = async (context: AuthContext, user: AuthUser) => {
  for (const operation of sanityOperationList()) {
    const skipReason = await getOperationSkipReason(context, user, operation.identifier);
    if (skipReason) {
      logApp.info('[DATA_SANITY_MANAGER] Data sanity operation skipped', { operation: operation.identifier, execution_type: operation.execution_type, reason: skipReason });
      continue;
    }
    const startTime = Date.now();
    let runError: any;
    let output;
    try {
      logApp.info('[DATA_SANITY_MANAGER] Executing data sanity operation', { operation: operation.identifier });
      if (operation.execution_type === 'run_once') {
        const estimatedResult = await operation.dryRun(context);
        logApp.info('[DATA_SANITY_MANAGER] Estimating run_once impact before actual run', { result: estimatedResult });
      }

      await markOperationAsRunning(context, DATA_SANITY_MANAGER_USER, operation.identifier);
      output = await operation.operationRun(context);
    } catch (e: any) {
      runError = e;
      logApp.warn('[DATA_SANITY_MANAGER] Data sanity operation failed', { operation: operation.identifier, cause: e });
    }
    const executionTimeMs = Date.now() - startTime;
    try {
      const runMessage = runError ? (runError?.message || String(runError)) : '';
      await markOperationAsExecuted(context, DATA_SANITY_MANAGER_USER, operation.identifier, executionTimeMs, !runError, runMessage, output);
      if (!runError) {
        logApp.info('[DATA_SANITY_MANAGER] Data sanity operation completed successfully', { operation: operation.identifier, executionTimeMs });
      }
    } catch (e: any) {
      logApp.error('[DATA_SANITY_MANAGER] Data sanity operation result could not be recorded', { operation: operation.identifier, cause: e });
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
  label: 'Data sanity manager',
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
