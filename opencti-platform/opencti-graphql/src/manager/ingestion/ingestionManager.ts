import type { SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { lockResources } from '../../lock/master-lock';
import conf, { booleanConf, logApp } from '../../config/conf';
import { TYPE_LOCK_ERROR } from '../../config/errors';
import { executionContext } from '../../utils/access';
import { rssExecutor } from './ingestionRss';
import { taxiiExecutor } from './ingestionTaxii';
import { csvExecutor } from './ingestionCsv';
import { jsonExecutor } from './ingestionJson';
import { SCHEDULE_TIME } from './ingestionUtils';

// Ingestion manager responsible to cleanup old data
// Each API will start is ingestion manager.
// If the lock is free, every API as the right to take it.
const INGESTION_MANAGER_KEY = conf.get('ingestion_manager:lock_key') || 'ingestion_manager_lock';

let running = false;

const ingestionHandler = async () => {
  logApp.debug('[OPENCTI-MODULE] INGESTION - Running ingestion handlers');
  let lock;
  try {
    // Lock the manager
    lock = await lockResources([INGESTION_MANAGER_KEY], { retryCount: 0 });
    running = true;
    // noinspection JSUnusedLocalSymbols
    const context = executionContext('ingestion_manager');
    const ingestionPromises = [];
    ingestionPromises.push(rssExecutor(context));
    ingestionPromises.push(taxiiExecutor(context));
    ingestionPromises.push(csvExecutor(context));
    ingestionPromises.push(jsonExecutor(context));
    await Promise.all(ingestionPromises);
  } catch (e: any) {
    // We dont care about failing to get the lock.
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI-MODULE] INGESTION - Ingestion manager already in progress by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Ingestion manager handling error', { cause: e, manager: 'INGESTION_MANAGER' });
    }
  } finally {
    running = false;
    if (lock) await lock.unlock();
  }
};

const initIngestionManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] INGESTION - Starting ingestion manager');
      scheduler = setIntervalAsync(async () => {
        await ingestionHandler();
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'INGESTION_MANAGER',
        enable: booleanConf('ingestion_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] INGESTION - Stopping ingestion manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const ingestionManager = initIngestionManager();

export default ingestionManager;
