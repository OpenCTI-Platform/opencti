import * as R from 'ramda';
import EventSource from 'eventsource';
import axios from 'axios';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import * as jsonpatch from 'fast-json-patch';
import conf, { logApp } from '../config/conf';
import { storeLoadById } from '../database/middleware';
import { SYSTEM_USER } from '../utils/access';
import { TYPE_LOCK_ERROR } from '../config/errors';
import Queue from '../utils/queue';
import { ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { createSyncHttpUri, httpBase, patchSync } from '../domain/connector';
import { EVENT_CURRENT_VERSION, lockResource } from '../database/redis';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { utcDate } from '../utils/format';
import { listEntities } from '../database/middleware-loader';
import { wait } from '../database/utils';
import { pushToSync } from '../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';

const SYNC_MANAGER_KEY = conf.get('sync_manager:lock_key') || 'sync_manager_lock';
const WAIT_TIME_ACTION = 2000;

const syncManagerInstance = (syncId) => {
  const MIN_QUEUE_SIZE = 100;
  const MAX_QUEUE_SIZE = 500;
  const lDelay = 10;
  const hDelay = 1000;
  // Variables
  let connectionId = null;
  let eventsQueue;
  let eventSource;
  let syncElement;
  let run = true;
  let lastState;
  let lastStateSaveTime;
  const handleEvent = (event) => {
    const { type, data, lastEventId } = event;
    const { data: stixData, context, version } = JSON.parse(data);
    if (version === EVENT_CURRENT_VERSION) {
      eventsQueue.enqueue({ id: lastEventId, type, data: stixData, context });
    }
  };
  const startStreamListening = async () => {
    eventsQueue = new Queue();
    syncElement = await storeLoadById(SYSTEM_USER, syncId, ENTITY_TYPE_SYNC);
    const { token, ssl_verify: ssl = false } = syncElement;
    const eventSourceUri = createSyncHttpUri(syncElement, false);
    logApp.info(`[OPENCTI] Running sync manager for ${syncId} (${eventSourceUri})`);
    eventSource = new EventSource(eventSourceUri, {
      rejectUnauthorized: ssl,
      headers: { authorization: `Bearer ${token}` },
    });
    eventSource.on('heartbeat', ({ lastEventId, type }) => {
      eventsQueue.enqueue({ id: lastEventId, type });
    });
    eventSource.on('create', (d) => handleEvent(d));
    eventSource.on('update', (d) => handleEvent(d));
    eventSource.on('delete', (d) => handleEvent(d));
    eventSource.on('merge', (d) => handleEvent(d));
    eventSource.on('connected', (d) => {
      connectionId = JSON.parse(d.data).connectionId;
    });
    eventSource.on('error', (error) => {
      logApp.error(`[OPENCTI] Error in sync manager for ${syncId}: ${error.message}`);
    });
    return syncElement;
  };
  const manageBackPressure = async ({ uri, token }, currentDelay) => {
    if (connectionId) {
      const connectionManagement = `${httpBase(uri)}stream/connection/${connectionId}`;
      const config = { headers: { authorization: `Bearer ${token}` } };
      if (currentDelay === lDelay && eventsQueue.getLength() > MAX_QUEUE_SIZE) {
        await axios.post(connectionManagement, { delay: hDelay }, config);
        logApp.info(`[OPENCTI] Sync connection setup to use ${hDelay} delay`);
        return hDelay;
      }
      if (currentDelay === hDelay && eventsQueue.getLength() < MIN_QUEUE_SIZE) {
        await axios.post(connectionManagement, { delay: lDelay }, config);
        logApp.info(`[OPENCTI] Sync connection setup to use ${lDelay} delay`);
        return lDelay;
      }
    }
    return currentDelay;
  };
  const transformDataWithReverseIdAndFilesData = async (data, context) => {
    const { token, uri } = syncElement;
    let processingData = data;
    // Reverse patch the id if modified
    const idOperations = (context?.reverse_patch ?? []).filter((patch) => patch.path === '/id');
    if (idOperations.length > 0) {
      const { newDocument: stixPreviousID } = jsonpatch.applyPatch(R.clone(data), idOperations);
      processingData = stixPreviousID;
    }
    // Handle file enrichment
    const entityFiles = processingData.extensions[STIX_EXT_OCTI].files ?? [];
    for (let index = 0; index < entityFiles.length; index += 1) {
      const entityFile = entityFiles[index];
      const { uri: fileUri } = entityFile;
      const config = { responseType: 'arraybuffer', headers: { authorization: `Bearer ${token}` } };
      const response = await axios.get(`${httpBase(uri)}${fileUri.substring(fileUri.indexOf('storage/get'))}`, config);
      entityFile.data = Buffer.from(response.data, 'utf-8').toString('base64');
    }
    return processingData;
  };
  const saveCurrentState = async (sync, eventId) => {
    const currentTime = new Date().getTime();
    const [time] = eventId.split('-');
    const dateTime = parseInt(time, 10);
    const eventDate = utcDate(dateTime).toISOString();
    if (lastStateSaveTime === undefined || (dateTime !== lastState && (currentTime - lastStateSaveTime) > 15000)) {
      logApp.info(`[OPENCTI] Sync ${sync.name}: saving state to ${eventDate}`);
      await patchSync(SYSTEM_USER, syncId, { current_state: eventDate });
      lastState = dateTime;
      lastStateSaveTime = currentTime;
    }
  };
  return {
    id: syncId,
    stop: () => {
      logApp.info(`[OPENCTI] Sync stopping manager for ${syncId}`);
      run = false;
      eventSource.close();
      eventsQueue = null;
    },
    start: async () => {
      run = true;
      const sync = await startStreamListening();
      lastState = sync.current_state;
      let currentDelay = lDelay;
      while (run) {
        const event = eventsQueue.dequeue();
        if (event) {
          try {
            currentDelay = manageBackPressure(sync, currentDelay);
            const { id: eventId, type: eventType, data, context } = event;
            if (eventType === 'heartbeat') {
              await saveCurrentState(sync, eventId);
            } else {
              const syncData = await transformDataWithReverseIdAndFilesData(data, context);
              const enrichedEvent = JSON.stringify({ id: eventId, type: eventType, data: syncData, context });
              const content = Buffer.from(enrichedEvent, 'utf-8').toString('base64');
              await pushToSync({ type: 'event', applicant_id: OPENCTI_SYSTEM_UUID, content });
              await saveCurrentState(sync, eventId);
            }
          } catch (e) {
            logApp.error('[OPENCTI] Sync error processing event', { error: e });
          }
        }
        await wait(10);
      }
    },
    isRunning: () => run,
  };
};

const initSyncManager = () => {
  let scheduler;
  let syncListening = true;
  const syncManagers = new Map();
  const processStep = async () => {
    // Get syncs definition
    const syncs = await listEntities(SYSTEM_USER, [ENTITY_TYPE_SYNC], { connectionFormat: false });
    // region Handle management of existing synchronizer
    for (let index = 0; index < syncs.length; index += 1) {
      const { id, running } = syncs[index];
      const syncInstance = syncManagers.get(id);
      if (syncInstance) {
        // Sync already exist
        if (running && !syncInstance.isRunning()) {
          syncInstance.start();
        }
        if (!running && syncInstance.isRunning()) {
          syncInstance.stop();
        }
      } else if (running) {
        // Sync is not currently running but it should be
        const manager = syncManagerInstance(id);
        syncManagers.set(id, manager);
        // noinspection ES6MissingAwait
        manager.start();
      }
    }
    // endregion
    // region Handle potential deletions
    const existingSyncs = syncs.map((s) => s.id);
    const deletedSyncs = Array.from(syncManagers.values()).filter((s) => !existingSyncs.includes(s.id));
    for (let deleteIndex = 0; deleteIndex < deletedSyncs.length; deleteIndex += 1) {
      const deletedSync = deletedSyncs[deleteIndex];
      deletedSync.stop();
      syncManagers.delete(deletedSync.id);
    }
    // endregion
  };
  const processingLoop = async () => {
    while (syncListening) {
      await processStep();
      await wait(WAIT_TIME_ACTION);
    }
    // Stopping
    // eslint-disable-next-line no-restricted-syntax
    for (const syncManager of syncManagers.values()) {
      if (syncManager.isRunning()) {
        await syncManager.stop();
      }
    }
  };
  const syncManagerHandler = async () => {
    let lock;
    try {
      logApp.debug('[OPENCTI-MODULE] Running sync manager');
      lock = await lockResource([SYNC_MANAGER_KEY]);
      await processingLoop();
    } catch (e) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.info('[OPENCTI-MODULE] Sync manager already in progress by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Sync manager failed to start', { error: e });
      }
    } finally {
      logApp.debug('[OPENCTI-MODULE] Sync manager done');
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      // processingLoopPromise = processingLoop();
      scheduler = setIntervalAsync(async () => {
        await syncManagerHandler();
      }, WAIT_TIME_ACTION);
    },
    shutdown: async () => {
      syncListening = false;
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const syncManager = initSyncManager();

export default syncManager;
