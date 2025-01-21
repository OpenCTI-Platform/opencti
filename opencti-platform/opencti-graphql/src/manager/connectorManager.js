import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { redisDeleteWorks, redisGetConnectorStatus, redisGetWork } from '../database/redis';
import { lockResources } from '../lock/master-lock';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { connectors } from '../database/repository';
import { elDeleteInstances, elList, elUpdate } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { READ_INDEX_HISTORY } from '../database/utils';
import { now, sinceNowInDays } from '../utils/format';

// Manage work created by connectors
// Update status to complete when needed
// Cleanup "batch_size" work in Elastic and Redis when complete "after works_day_range" days
const SCHEDULE_TIME = conf.get('connector_manager:interval') || 60000;
const CONNECTOR_MANAGER_KEY = conf.get('connector_manager:lock_key') || 'connector_manager_lock';
const CONNECTOR_WORK_RANGE = conf.get('connector_manager:works_day_range') || 7;
const BATCH_SIZE = conf.get('connector_manager:batch_size') || 10000;
let running = false;

const closeOldWorks = async (context, connector) => {
  // Get current status from Redis
  const status = await redisGetConnectorStatus(connector.internal_id);
  // If status is here we can try to close all old open works
  if (status) {
    const [,, timestamp] = status.split('_');
    // Get all works created before the current one and put a complete status on it.
    const filters = {
      mode: 'and',
      filters: [
        { key: 'connector_id', values: [connector.internal_id] },
        { key: 'status', values: ['wait', 'progress'] },
        { key: 'timestamp', values: [timestamp], operator: 'lt' }
      ],
      filterGroups: [],
    };
    const queryCallback = async (elements) => {
      for (let i = 0; i < elements.length; i += 1) {
        const element = elements[i];
        try {
          // If element is too old, just delete it
          if (sinceNowInDays(element.timestamp) > CONNECTOR_WORK_RANGE) {
            await elDeleteInstances([element]);
          } else { // If not, update the status to complete + the number of processed elements
            const currentWorkStatus = await redisGetWork(element.internal_id);
            if (currentWorkStatus) {
              const params = { completed_time: now(), completed_number: parseInt(currentWorkStatus.import_processed_number, 10) };
              const sourceScript = `ctx._source['status'] = "complete";
                  ctx._source['completed_time'] = params.completed_time;
                  ctx._source['completed_number'] = params.completed_number;`;
              await elUpdate(element._index, element.internal_id, {
                script: {
                  source: sourceScript,
                  lang: 'painless',
                  params
                }
              });
            }
          }
          // Delete redis tracking key
          await redisDeleteWorks(element.internal_id);
        } catch (e) {
          logApp.error('[OPENCTI-MODULE] Connector manager error processing work closing', { cause: e });
        }
      }
    };
    await elList(context, SYSTEM_USER, [READ_INDEX_HISTORY], {
      filters,
      noFiltersChecking: true,
      types: ['Work'],
      orderBy: 'timestamp',
      connectionFormat: false,
      baseData: true,
      baseFields: ['internal_id', 'timestamp'],
      maxSize: BATCH_SIZE,
      callback: queryCallback,
    });
  }
};

export const deleteCompletedWorks = async (context, connector) => {
  const filters = {
    mode: 'and',
    filters: [
      { key: 'connector_id', values: [connector.internal_id] },
      { key: 'status', values: ['complete'] },
      { key: 'completed_time', values: [`now-${CONNECTOR_WORK_RANGE}d/d`], operator: 'lte' }
    ],
    filterGroups: [],
  };
  const queryCallback = async (elements) => {
    const message = `[WORKS] Deleting ${elements.length} works for ${connector.name}`;
    logApp.info(message);
    const ids = elements.map((w) => w.internal_id);
    await redisDeleteWorks(ids);
    await elDeleteInstances(elements);
  };
  await elList(context, SYSTEM_USER, [READ_INDEX_HISTORY], {
    filters,
    types: ['Work'],
    orderBy: 'timestamp',
    noFiltersChecking: true,
    connectionFormat: false,
    baseData: true,
    baseFields: ['internal_id'],
    maxSize: BATCH_SIZE,
    callback: queryCallback,
  });
};

const connectorHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResources([CONNECTOR_MANAGER_KEY], { retryCount: 0 });
    running = true;
    const context = executionContext('connector_manager');
    // Execute the cleaning
    const platformConnectors = await connectors(context, SYSTEM_USER);
    for (let index = 0; index < platformConnectors.length; index += 1) {
      lock.signal.throwIfAborted();
      const platformConnector = platformConnectors[index];
      // Force close all needed works
      await closeOldWorks(context, platformConnector);
      // Cleanup too old complete works
      await deleteCompletedWorks(context, platformConnector);
    }
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Connector manager already started by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Connector manager handling error', { cause: e, manager: 'CONNECTOR_MANAGER' });
    }
  } finally {
    running = false;
    logApp.debug('[OPENCTI-MODULE] Connector manager done');
    if (lock) await lock.unlock();
  }
};

const initConnectorManager = () => {
  let scheduler;
  return {
    start: async () => {
      scheduler = setIntervalAsync(async () => {
        await connectorHandler();
      }, SCHEDULE_TIME);
    },
    status: async () => {
      return {
        id: 'CONNECTOR_MANAGER',
        enable: booleanConf('connector_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping connector manager');
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const connectorManager = initConnectorManager();

export default connectorManager;
