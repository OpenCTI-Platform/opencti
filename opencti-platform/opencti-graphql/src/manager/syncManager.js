import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { patchSync } from '../domain/connector';
import { lockResources } from '../lock/master-lock';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { utcDate } from '../utils/format';
import { topEntitiesList, storeLoadById } from '../database/middleware-loader';
import { isEmptyField, wait } from '../database/utils';
import { pushToWorkerForConnector } from '../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { getHttpClient } from '../utils/http-client';
import { createSyncHttpUri, httpBase } from '../domain/connector-utils';
import { EVENT_CURRENT_VERSION } from '../database/stream/stream-utils';
import { storeSyncConsumerMetrics, clearSyncConsumerMetrics } from '../graphql/syncConsumerMetrics';
import { createParser } from 'eventsource-parser';

const SYNC_MANAGER_KEY = conf.get('sync_manager:lock_key') || 'sync_manager_lock';
const SCHEDULE_TIME = conf.get('sync_manager:interval') || 10000;
const WAIT_TIME_ACTION = 2000;

const syncManagerInstance = (syncId) => {
  // Variables
  let connectionId = null;
  let connectedAt = null; // ISO string, when the sync connected to the remote stream
  let lastState;
  let lastStateSaveTime;
  let lastEventDate; // Track the last saved event date (ISO string) for reconnection
  let running = false;
  let abortController = null;
  // Async generator that yields SSE events from a raw HTTP stream.
  // Backpressure is natural: when the consumer is busy processing an event,
  // the generator is suspended, bytes are not read from the socket,
  // TCP receive buffer fills up, and flow control throttles the server.
  const streamEvents = async function* (sseUri, syncElement) {
    const { token, ssl_verify: ssl = false } = syncElement;
    const headers = !isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined;
    abortController = new AbortController();
    const streamClient = getHttpClient({ headers, rejectUnauthorized: ssl, responseType: 'stream' });
    const response = await streamClient.get(sseUri, { signal: abortController.signal });
    const queue = [];
    const parser = createParser({
      onEvent(event) {
        queue.push({ type: event.event ?? 'message', data: event.data, lastEventId: event.id ?? '' });
      },
    });
    for await (const chunk of response.data) {
      parser.feed(chunk.toString());
      while (queue.length > 0) {
        yield queue.shift();
      }
    }
  };
  const transformDataWithReverseIdAndFilesData = async (sync, httpClient, data, context) => {
    const { uri } = sync;
    const processingData = { ...data };
    // Reverse patch the id if modified
    const idOperation = (context?.reverse_patch ?? []).find((patch) => patch.path === '/id');
    // Handle file enrichment
    const entityFiles = processingData.extensions[STIX_EXT_OCTI].files ?? [];
    for (let index = 0; index < entityFiles.length; index += 1) {
      const entityFile = entityFiles[index];
      const { uri: fileUri } = entityFile;
      try {
        const response = await httpClient.get(`${httpBase(uri)}${fileUri.substring(fileUri.indexOf('storage/get'))}`);
        entityFile.data = Buffer.from(response.data, 'utf-8').toString('base64');
      } catch (e) {
        logApp.warn('[OPENCTI] Sync: Error when trying to get file from storage. Skipping file.', { fileUri, message: e.message });
      }
    }
    return { data: processingData, previous_standard: idOperation?.value };
  };
  const saveCurrentState = async (context, type, eventId) => {
    const currentTime = new Date().getTime();
    const [time] = eventId.split('-');
    const dateTime = parseInt(time, 10);
    const eventDate = utcDate(dateTime).toISOString();
    if (lastStateSaveTime === undefined || (dateTime !== lastState && (currentTime - lastStateSaveTime) > 15000)) {
      logApp.info(`[OPENCTI] Sync ${syncId}: saving state from ${type} to ${eventId}/${eventDate}`);
      await patchSync(context, SYSTEM_USER, syncId, { current_state_date: eventDate });
      lastState = dateTime;
      lastStateSaveTime = currentTime;
      lastEventDate = eventDate;
    }
  };
  const isRunning = () => running;
  return {
    id: syncId,
    stop: () => {
      logApp.info(`[OPENCTI] Sync ${syncId}: stopping manager`);
      running = false;
      if (abortController) abortController.abort();
      clearSyncConsumerMetrics(syncId).catch(() => {});
    },
    start: async (context) => {
      running = true;
      logApp.info(`[OPENCTI] Sync ${syncId}: starting manager`);
      const sync = await storeLoadById(context, SYSTEM_USER, syncId, ENTITY_TYPE_SYNC);
      const synchronized = sync.synchronized ?? false;
      const { token, ssl_verify: ssl = false } = sync;
      const headers = !isEmptyField(token) ? { authorization: `Bearer ${token}` } : undefined;
      const httpClientOptions = { headers, rejectUnauthorized: ssl, responseType: 'arraybuffer' };
      const httpClient = getHttpClient(httpClientOptions);
      lastState = sync.current_state_date;
      lastEventDate = sync.current_state_date;
      // Reconnection loop: on stream error/close, reconnect from the last saved state.
      // This replaces EventSource's built-in auto-reconnect.
      while (running) {
        try {
          const sseUri = createSyncHttpUri(sync, lastEventDate ?? lastState, false);
          for await (const event of streamEvents(sseUri, sync)) {
            if (!running) break;
            const { type: eventType, data: eventData, lastEventId } = event;
            // Handle connection event
            if (eventType === 'connected') {
              const connectedData = JSON.parse(eventData);
              connectionId = connectedData.connectionId;
              connectedAt = new Date().toISOString();
              logApp.info(`[OPENCTI] Sync ${syncId}: listening ${sseUri} with id ${connectionId}`);
              continue;
            }
            // Handle heartbeat - just save state, no data to process
            if (eventType === 'heartbeat') {
              await saveCurrentState(context, eventType, lastEventId);
              continue;
            }
            // Handle consumer_metrics - store metrics received from the remote stream
            if (eventType === 'consumer_metrics') {
              try {
                const metrics = JSON.parse(eventData);
                const syncConnectedAt = connectedAt || new Date().toISOString();
                const syncConnectionId = connectionId || '';
                await storeSyncConsumerMetrics(syncId, syncConnectionId, syncConnectedAt, metrics, lastEventId);
              } catch (metricsError) {
                logApp.warn('[OPENCTI] Sync: Error storing consumer metrics', { syncId, cause: metricsError });
              }
              continue;
            }
            // Handle data events (create, update, delete, merge)
            const { data: stixData, context: eventContext, version, event_id } = JSON.parse(eventData);
            if (version !== EVENT_CURRENT_VERSION) continue;
            // Process the event with retry: if pushToWorkerForConnector or saveCurrentState fails,
            // retry indefinitely until it succeeds or the manager is stopped.
            let processed = false;
            while (!processed && running) {
              try {
                const { data: syncData, previous_standard } = await transformDataWithReverseIdAndFilesData(sync, httpClient, stixData, eventContext);
                const enrichedEvent = JSON.stringify({ id: lastEventId, type: eventType, data: syncData, context: eventContext });
                const content = Buffer.from(enrichedEvent, 'utf-8').toString('base64');
                await pushToWorkerForConnector(sync.internal_id, {
                  type: 'event',
                  event_id,
                  synchronized,
                  previous_standard,
                  update: true,
                  applicant_id: sync.user_id ?? OPENCTI_SYSTEM_UUID,
                  content,
                });
                await saveCurrentState(context, 'event', lastEventId);
                processed = true;
              } catch (processingError) {
                logApp.error('[OPENCTI-MODULE] Sync manager event handling error, retrying...', {
                  cause: processingError, id: syncId, manager: 'SYNC_MANAGER',
                });
                await wait(5000);
              }
            }
          }
          // Stream ended cleanly (server closed) — reconnect if still running
          if (running) {
            logApp.info(`[OPENCTI] Sync ${syncId}: stream ended, reconnecting...`);
          }
        } catch (streamError) {
          if (!running) break; // Abort was intentional (stop() was called)
          logApp.warn('[OPENCTI] Sync stream error, reconnecting...', {
            id: syncId, manager: 'SYNC_MANAGER', cause: streamError,
          });
          await wait(5000);
        }
      }
      logApp.info(`[OPENCTI] Sync ${syncId}: manager stopped`);
    },
    isRunning,
  };
};

const initSyncManager = () => {
  let scheduler;
  let syncListening = true;
  let managerRunning = false;
  const syncManagers = new Map();
  const processStep = async () => {
    // Get syncs definition
    const context = executionContext('sync_manager');
    const syncs = await topEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_SYNC]);
    // region Handle management of existing synchronizer
    for (let index = 0; index < syncs.length; index += 1) {
      const { id, running } = syncs[index];
      const syncInstance = syncManagers.get(id);
      if (syncInstance) {
        // Sync already exist
        if (running && !syncInstance.isRunning()) {
          syncInstance.start(context);
        }
        if (!running && syncInstance.isRunning()) {
          syncInstance.stop();
        }
      } else if (running) {
        // Sync is not currently running but it should be
        const manager = syncManagerInstance(id);
        syncManagers.set(id, manager);
        // noinspection ES6MissingAwait
        manager.start(context).catch((reason) => logApp.error('[SYNC MANAGER] global error', { reason }));
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
  const processingLoop = async (lock) => {
    while (syncListening) {
      lock.signal.throwIfAborted();
      await processStep();
      await wait(WAIT_TIME_ACTION);
    }
    // Stopping
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
      lock = await lockResources([SYNC_MANAGER_KEY], { retryCount: 0 });
      managerRunning = true;
      await processingLoop(lock);
    } catch (e) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Sync manager already in progress by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Sync manager handler error', { cause: e, manager: 'SYNC_MANAGER' });
      }
    } finally {
      managerRunning = false;
      logApp.debug('[OPENCTI-MODULE] Sync manager done');
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      scheduler = setIntervalAsync(async () => {
        await syncManagerHandler();
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'SYNC_MANAGER',
        enable: booleanConf('sync_manager:enabled', false),
        running: managerRunning,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping Sync manager');
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
