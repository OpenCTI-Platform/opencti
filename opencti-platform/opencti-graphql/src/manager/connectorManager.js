import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { lockResource, redisDeleteWorks, redisGetConnectorStatus, redisGetWork } from '../database/redis';
import conf, { logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { connectors } from '../database/repository';
import { elDeleteInstances, elUpdate } from '../database/engine';
import { elList } from '../database/middleware-loader';
import { SYSTEM_USER } from '../utils/access';
import { INDEX_HISTORY } from '../database/utils';
import { now, sinceNowInDays } from '../utils/format';

// Expired manager responsible to monitor expired elements
// In order to change the revoked attribute to true
// Each API will start is manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('connector_manager:interval');
const CONNECTOR_MANAGER_KEY = conf.get('connector_manager:lock_key');
const CONNECTOR_WORK_RANGE = conf.get('connector_manager:works_day_range');

const closeOldWorks = async (connector) => {
  // Get current status from Redis
  const status = await redisGetConnectorStatus(connector.internal_id);
  // If status is here we can try to close all old open works
  if (status) {
    const [,, timestamp] = status.split('_');
    // Get all works created before the current one and put a complete status on it.
    const filters = [
      { key: 'event_source_id', values: [connector.internal_id] },
      { key: 'status', values: ['wait', 'progress'] },
      { key: 'timestamp', values: [timestamp], operator: 'lt' }
    ];
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
              const params = { completed_time: now(), completed_number: currentWorkStatus.import_processed_number };
              const sourceScript = `ctx._source['status'] = "complete";
                  ctx._source['completed_time'] = params.completed_time;
                  ctx._source['completed_number'] = params.completed_number;`;
              await elUpdate(INDEX_HISTORY, element.internal_id, {
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
          logApp.info('[OPENCTI-MODULE] Connector manager error processing work closing', { error: e });
        }
      }
    };
    await elList(SYSTEM_USER, [INDEX_HISTORY], {
      filters,
      types: ['Work'],
      connectionFormat: false,
      callback: queryCallback
    });
  }
};

const deleteCompletedWorks = async (connector) => {
  const filters = [
    { key: 'event_source_id', values: [connector.internal_id] },
    { key: 'status', values: ['complete'] },
    { key: 'completed_time', values: [`now-${CONNECTOR_WORK_RANGE}d/d`], operator: 'lte' }
  ];
  const queryCallback = async (elements) => {
    const message = `[WORKS] Deleting ${elements.length} works for ${connector.name}`;
    logApp.info(message);
    const ids = elements.map((w) => w.internal_id);
    await redisDeleteWorks(ids);
    await elDeleteInstances(elements);
  };
  await elList(SYSTEM_USER, [INDEX_HISTORY], {
    filters,
    types: ['Work'],
    connectionFormat: false,
    callback: queryCallback
  });
};

const connectorHandler = async () => {
  let lock;
  try {
    // Lock the manager
    lock = await lockResource([CONNECTOR_MANAGER_KEY]);
    // Execute the cleaning
    const platformConnectors = await connectors(SYSTEM_USER);
    for (let index = 0; index < platformConnectors.length; index += 1) {
      const platformConnector = platformConnectors[index];
      // Force close all needed works
      await closeOldWorks(platformConnector);
      // Cleanup too old complete works
      await deleteCompletedWorks(platformConnector);
    }
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.info('[OPENCTI-MODULE] Connector manager already started by another API');
    } else {
      logApp.error('[OPENCTI-MODULE] Connector manager failed to start', { error: e });
    }
  } finally {
    logApp.debug('[OPENCTI-MODULE] Connector manager done');
    if (lock) await lock.unlock();
  }
};

const initConnectorManager = () => {
  let scheduler;
  return {
    start: () => {
      logApp.info('[OPENCTI-MODULE] Running connector manager');
      scheduler = setIntervalAsync(async () => {
        await connectorHandler();
      }, SCHEDULE_TIME);
    },
    shutdown: async () => {
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const connectorManager = initConnectorManager();

export default connectorManager;
