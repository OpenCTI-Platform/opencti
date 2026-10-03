import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext } from '../utils/access';
import { runProvenanceBackfillBatch } from '../modules/provenance/provenance-backfill';

const PROVENANCE_BACKFILL_MANAGER_ENABLED = booleanConf('provenance_backfill_manager:enabled', true);
const PROVENANCE_BACKFILL_MANAGER_KEY = conf.get('provenance_backfill_manager:lock_key') || 'provenance_backfill_manager_lock';
const SCHEDULE_TIME = conf.get('provenance_backfill_manager:interval') || 30000;
const BATCH_SIZE = conf.get('provenance_backfill_manager:batch_size') || 500;

/**
 * Rebuild, batch after batch, the assertions of the knowledge that existed before provenance tracking,
 * from the history and the works. Resumable: the cursor is persisted after every batch.
 */
export const provenanceBackfillHandler = async () => {
  const context = executionContext('provenance_backfill_manager');
  const state = await runProvenanceBackfillBatch(context, { batchSize: BATCH_SIZE });
  if (state && state.status === 'completed' && state.completed_at) {
    logApp.debug('[OPENCTI-MODULE] Provenance backfill completed', { processed: state.processed, updated: state.updated, errors: state.errors });
  } else if (state) {
    logApp.info('[OPENCTI-MODULE] Provenance backfill in progress', { processed: state.processed, expected: state.expected, errors: state.errors });
  }
};

const PROVENANCE_BACKFILL_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'PROVENANCE_BACKFILL_MANAGER',
  label: 'Provenance backfill manager',
  executionContext: 'provenance_backfill_manager',
  cronSchedulerHandler: {
    handler: provenanceBackfillHandler,
    interval: SCHEDULE_TIME,
    lockKey: PROVENANCE_BACKFILL_MANAGER_KEY,
  },
  enabledByConfig: PROVENANCE_BACKFILL_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(PROVENANCE_BACKFILL_MANAGER_DEFINITION);
