import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { DATA_SANITY_MANAGER_USER, executionContext } from '../utils/access';
import type { AuthContext } from '../types/user';
import { findDataSanityByFixName, findForceRunFixes, hasFixBeenExecuted, markFixAsExecuted, registerOnDemandFixes } from '../modules/dataSanity/dataSanity-domain';
import { type SanityFix, sanityFixList } from './dataSanityManager/dataSanityManager-configuration';

const DATA_SANITY_MANAGER_ID = 'DATA_SANITY_MANAGER';
const DATA_SANITY_MANAGER_LABEL = 'Data sanity manager';
const DATA_SANITY_MANAGER_CONTEXT = 'data_sanity_manager';

const DATA_SANITY_MANAGER_ENABLED = booleanConf('data_sanity_manager:enabled', true);
const DATA_SANITY_MANAGER_KEY = conf.get('data_sanity_manager:lock_key') || 'data_sanity_manager_lock';
const SCHEDULE_TIME = conf.get('data_sanity_manager:interval') || 14400000; // 4 hours

/**
 * Determines if a fix should be skipped based on its execution_type and state in ElasticSearch.
 * - run_once: skip if already executed (unless force_run is set)
 * - on_demand: skip unless force_run is set in the DataSanity entity
 * - periodic: never skip
 */
const shouldSkipFix = async (context: AuthContext, fix: SanityFix): Promise<boolean> => {
  switch (fix.execution_type) {
    case 'periodic':
      return false; // always run
    case 'run_once': {
      return await hasFixBeenExecuted(context, fix.name);
    }
    case 'on_demand': {
      const entity = await findDataSanityByFixName(context, fix.name);
      // Only run if entity exists and force_run is true
      return !entity?.force_run;
    }
    default:
      return false;
  }
};

export const dataSanityForceRunHandler = async (context: AuthContext) => {
  // Run force_run fixes from ElasticSearch (fixes triggered on demand via the force_run flag)
  const forceRunEntities = await findForceRunFixes(context, DATA_SANITY_MANAGER_USER);
  const alreadyExecutedInThisRun = sanityFixList().map((f) => f.name);
  for (const entity of forceRunEntities) {
    // Skip if already handled in the SANITY_FIXES loop above
    if (alreadyExecutedInThisRun.includes(entity.fix_name)) {
      continue;
    }
    // Find the corresponding fix function in the registry
    const fix = sanityFixList().find((f) => f.name === entity.fix_name);
    if (!fix) {
      logApp.warn('[OPENCTI-MODULE] Force run requested for unknown fix, skipping', { fix_name: entity.fix_name });
      continue;
    }
    const startTime = Date.now();
    try {
      logApp.info('[OPENCTI-MODULE] Executing force_run data sanity fix', { fix: fix.name });
      await fix.fn(context);
      const executionTimeMs = Date.now() - startTime;
      await markFixAsExecuted(context, DATA_SANITY_MANAGER_USER, fix.name, executionTimeMs);
      logApp.info('[OPENCTI-MODULE] Force_run data sanity fix completed successfully', { fix: fix.name, executionTimeMs });
    } catch (e: any) {
      const executionTimeMs = Date.now() - startTime;
      const failureMessage = e?.message || String(e);
      logApp.error('[OPENCTI-MODULE] Force_run data sanity fix failed', { fix: fix.name, error: e });
      await markFixAsExecuted(context, DATA_SANITY_MANAGER_USER, fix.name, executionTimeMs, failureMessage).catch(() => {});
    }
  }
};

export const dataSanityListHandler = async (context: AuthContext) => {
  for (const fix of sanityFixList()) {
    const shouldSkip = await shouldSkipFix(context, fix);
    if (shouldSkip) {
      logApp.debug('[OPENCTI-MODULE] Data sanity fix skipped', { fix: fix.name, execution_type: fix.execution_type });
      continue;
    }
    const startTime = Date.now();
    try {
      logApp.info('[OPENCTI-MODULE] Executing data sanity fix', { fix: fix.name });
      await fix.fn(context);
      const executionTimeMs = Date.now() - startTime;
      await markFixAsExecuted(context, DATA_SANITY_MANAGER_USER, fix.name, executionTimeMs);
      logApp.info('[OPENCTI-MODULE] Data sanity fix completed successfully', { fix: fix.name, executionTimeMs });
    } catch (e: any) {
      const executionTimeMs = Date.now() - startTime;
      const failureMessage = e?.message || String(e);
      logApp.error('[OPENCTI-MODULE] Data sanity fix failed', { fix: fix.name, error: e });
      await markFixAsExecuted(context, DATA_SANITY_MANAGER_USER, fix.name, executionTimeMs, failureMessage).catch(() => {});
    }
  }
};

export const dataSanityHandler = async () => {
  const context = executionContext(DATA_SANITY_MANAGER_CONTEXT);
  logApp.info('[OPENCTI-MODULE] Running data sanity manager handler', { manager: DATA_SANITY_MANAGER_ID });
  // Register on_demand fixes in ElasticSearch so they can be triggered via force_run later
  await registerOnDemandFixes(context, DATA_SANITY_MANAGER_USER);
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
