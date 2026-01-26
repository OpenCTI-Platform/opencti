import amqp from 'amqplib/callback_api';
import util from 'util';
import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import { LRUCache } from 'lru-cache';
import conf, { booleanConf, configureCA, loadCert, logApp } from '../config/conf';
import { DatabaseError } from '../config/errors';
import { SYSTEM_USER } from '../utils/access';
import { telemetry } from '../config/tracing';
import { isEmptyField, RABBIT_QUEUE_PREFIX, wait } from './utils';
import { getHttpClient } from '../utils/http-client';
import { fullEntitiesList } from './middleware-loader';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { s3ConnectionConfig } from './raw-file-storage';

export const CONNECTOR_EXCHANGE = `${RABBIT_QUEUE_PREFIX}amqp.connector.exchange`;
export const WORKER_EXCHANGE = `${RABBIT_QUEUE_PREFIX}amqp.worker.exchange`;

const USE_SSL = booleanConf('rabbitmq:use_ssl', false);
const QUEUE_TYPE = conf.get('rabbitmq:queue_type');
const readFileFromConfig = (configKey) => (conf.get(configKey) ? loadCert(conf.get(configKey)) : undefined);
const RABBITMQ_CA = (conf.get('rabbitmq:use_ssl_ca') ?? []).map((path) => loadCert(path));
const RABBITMQ_CA_CERT = readFileFromConfig('rabbitmq:use_ssl_cert');
const RABBITMQ_CA_KEY = readFileFromConfig('rabbitmq:use_ssl_key');
const RABBITMQ_CA_PFX = readFileFromConfig('rabbitmq:use_ssl_pfx');
const RABBITMQ_CA_PASSPHRASE = conf.get('rabbitmq:use_ssl_passphrase');
const RABBITMQ_REJECT_UNAUTHORIZED = booleanConf('rabbitmq:use_ssl_reject_unauthorized', false);
const RABBITMQ_MGMT_REJECT_UNAUTHORIZED = booleanConf('rabbitmq:management_ssl_reject_unauthorized', false);
export const BACKGROUND_TASK_QUEUES = parseInt(conf.get('app:task_scheduler:max_queues_breakdown') ?? '4', 10);
const RABBITMQ_PUSH_QUEUE_PREFIX = `${RABBIT_QUEUE_PREFIX}push_`;
const RABBITMQ_LISTEN_QUEUE_PREFIX = `${RABBIT_QUEUE_PREFIX}listen_`;
const HOSTNAME = conf.get('rabbitmq:hostname');
const PORT = conf.get('rabbitmq:port');
const USERNAME = conf.get('rabbitmq:username');
const PASSWORD = conf.get('rabbitmq:password');
const VHOST = conf.get('rabbitmq:vhost');
const VHOST_PATH = VHOST === '/' ? '' : `/${VHOST}`;
const USE_SSL_MGMT = booleanConf('rabbitmq:management_ssl', false);
const HOSTNAME_MGMT = conf.get('rabbitmq:hostname_management') || HOSTNAME;
const PORT_MGMT = conf.get('rabbitmq:port_management');

const amqpUri = () => {
  const ssl = USE_SSL ? 's' : '';
  return `amqp${ssl}://${HOSTNAME}:${PORT}${VHOST_PATH}`;
};

const amqpCred = () => {
  return { credentials: amqp.credentials.plain(USERNAME, PASSWORD) };
};

const getConnectionOptions = () => {
  return USE_SSL ? {
    ...amqpCred(),
    ...configureCA(RABBITMQ_CA),
    cert: RABBITMQ_CA_CERT,
    key: RABBITMQ_CA_KEY,
    pfx: RABBITMQ_CA_PFX,
    passphrase: RABBITMQ_CA_PASSPHRASE,
    rejectUnauthorized: RABBITMQ_REJECT_UNAUTHORIZED,
  } : amqpCred();
};

// region Persistent Publisher Connection
// Single persistent connection for sequential message publishing
// This avoids creating a new connection for every message while maintaining order
// Connection will automatically reconnect and block sends until recovery
let _persistentConnection = null; // Prefixed with _ as it's assigned but read access is via the connection object
let persistentChannel = null;
let connectionPromise = null;
let isReconnecting = false;
let isIntentionalClose = false; // Flag to prevent reconnection during intentional cleanup

// Configuration for reconnection
const RECONNECT_INITIAL_DELAY = 1000; // 1 second
const RECONNECT_MAX_DELAY = 30000; // 30 seconds max
const RECONNECT_MULTIPLIER = 2; // Exponential backoff

/**
 * Create a new connection to RabbitMQ with automatic reconnection
 */
const createConnection = () => {
  return new Promise((resolve, reject) => {
    const connOptions = getConnectionOptions();
    amqp.connect(amqpUri(), connOptions, (err, conn) => {
      if (err) {
        reject(err);
        return;
      }

      _persistentConnection = conn;
      logApp.info('[RABBITMQ] Persistent publisher connection established');

      conn.on('error', (connError) => {
        logApp.error('[RABBITMQ] Persistent connection error', { cause: connError });
      });

      conn.on('close', () => {
        logApp.warn('[RABBITMQ] Persistent connection closed');
        _persistentConnection = null;
        persistentChannel = null;
        connectionPromise = null;
        // Trigger reconnection in background (unless this is an intentional cleanup close)
        if (!isReconnecting && !isIntentionalClose) {
          void reconnectWithBackoff();
        }
        isIntentionalClose = false; // Reset flag after handling
      });

      // Create a confirm channel for reliable publishing
      conn.createConfirmChannel((channelError, channel) => {
        if (channelError) {
          logApp.error('[RABBITMQ] Failed to create confirm channel', { cause: channelError });
          // Clean up the connection to avoid leaks - set flag to prevent auto-reconnect
          isIntentionalClose = true;
          _persistentConnection = null;
          persistentChannel = null;
          connectionPromise = null;
          try {
            conn.close();
          } catch (_closeError) {
            // Ignore close errors during cleanup
            isIntentionalClose = false; // Reset flag if close fails
          }
          reject(channelError);
          return;
        }

        channel.on('error', (chError) => {
          logApp.error('[RABBITMQ] Persistent channel error', { cause: chError });
          persistentChannel = null;
          // Close the connection to trigger reconnection and avoid dangling connections
          if (_persistentConnection) {
            try {
              _persistentConnection.close();
            } catch (_e) {
              // Ignore close errors - connection may already be closing
            }
          }
        });

        channel.on('close', () => {
          logApp.warn('[RABBITMQ] Persistent channel closed');
          persistentChannel = null;
          // Close the connection to trigger reconnection and avoid dangling connections
          if (_persistentConnection) {
            try {
              _persistentConnection.close();
            } catch (_e) {
              // Ignore close errors - connection may already be closing
            }
          }
        });

        persistentChannel = channel;
        resolve(channel);
      });
    });
  });
};

/**
 * Reconnect with exponential backoff
 * This runs in the background and keeps trying until successful
 */
const reconnectWithBackoff = async () => {
  if (isReconnecting) {
    return; // Already reconnecting
  }

  isReconnecting = true;
  let currentDelay = RECONNECT_INITIAL_DELAY;
  let attempt = 1;

  while (!persistentChannel) {
    logApp.info(`[RABBITMQ] Attempting to reconnect (attempt ${attempt})...`);
    try {
      connectionPromise = createConnection();
      await connectionPromise;
      connectionPromise = null;
      logApp.info('[RABBITMQ] Reconnection successful');
      isReconnecting = false;
      return;
    } catch (err) {
      connectionPromise = null;
      logApp.warn(`[RABBITMQ] Reconnection attempt ${attempt} failed, retrying in ${currentDelay}ms`, { cause: err });
      await wait(currentDelay);
      // Exponential backoff with max limit
      currentDelay = Math.min(currentDelay * RECONNECT_MULTIPLIER, RECONNECT_MAX_DELAY);
      attempt += 1;
    }
  }

  isReconnecting = false;
};

/**
 * Safely await a connection promise, catching any errors
 * Returns true if connection succeeded, false otherwise
 */
const safeAwaitConnection = async () => {
  if (connectionPromise) {
    try {
      await connectionPromise;
      return true;
    } catch (_e) {
      // Connection attempt failed, will retry
      return false;
    }
  }
  return false;
};

/**
 * Get a healthy channel, waiting for reconnection if necessary
 * This will block until a connection is available - never throws
 */
const getPersistentChannel = async () => {
  // Return immediately if channel is already available
  if (persistentChannel) {
    return persistentChannel;
  }

  // Loop until we have a healthy channel
  while (!persistentChannel) {
    // If connection is in progress, wait for it (with error handling)
    if (connectionPromise) {
      await safeAwaitConnection();
      // Check if we got a channel
      if (persistentChannel) {
        return persistentChannel;
      }
    }

    // If reconnection is in progress, wait a bit and check again
    if (isReconnecting) {
      logApp.debug('[RABBITMQ] Waiting for reconnection to complete...');
      await wait(100);
      continue;
    }

    // No connection exists and no reconnection in progress, create one
    connectionPromise = createConnection();
    const success = await safeAwaitConnection();
    connectionPromise = null;

    if (success && persistentChannel) {
      return persistentChannel;
    }

    // Connection failed, start reconnection in background
    if (!isReconnecting) {
      logApp.error('[RABBITMQ] Connection failed, starting reconnection');
      void reconnectWithBackoff();
    }

    // Wait a bit before next iteration
    await wait(100);
  }

  return persistentChannel;
};

/**
 * Internal publish function with confirm channel and backpressure handling
 *
 * Guarantees:
 * - At-least-once delivery: Messages are retried on failure
 * - Backpressure: Waits for drain when channel buffer is full
 *
 * Note: Around connection failures, there's a small window where a message
 * could be accepted by the buffer but the confirm never received. Retry logic
 * may cause duplicate delivery in this edge case (at-least-once, not exactly-once).
 */
const publishWithConfirm = (channel, exchangeName, routingKey, message) => {
  return new Promise((resolve, reject) => {
    try {
      // With confirm channels, the callback is called when broker acknowledges the message
      const canContinue = channel.publish(
        exchangeName,
        routingKey,
        Buffer.from(message),
        { deliveryMode: 2 },
        (err) => {
          if (err) {
            reject(err);
          } else {
            resolve(true);
          }
        },
      );

      // Handle backpressure: if channel buffer is full, wait for drain before allowing more
      // This prevents unbounded memory growth under high load
      if (!canContinue) {
        logApp.debug('[RABBITMQ] Channel buffer full, waiting for drain...');
        channel.once('drain', () => {
          logApp.debug('[RABBITMQ] Channel buffer drained, ready to continue');
          // Note: The message is already queued and will be confirmed via callback above
          // This drain handler is for flow control awareness, not for this specific message
        });
      }
    } catch (err) {
      // Channel might have been closed between getting it and publishing
      // Reset channel and reject so caller can retry
      persistentChannel = null;
      reject(err);
    }
  });
};

/**
 * Send a message using the persistent connection
 * This will block and wait for reconnection if the connection is lost
 *
 * Note: Callers are responsible for ensuring ordering by using sequential awaits.
 * All current usage patterns either send to different queues (ordering irrelevant)
 * or use await in loops (natural ordering via JavaScript's event loop).
 */
const sendPersistent = async (exchangeName, routingKey, message) => {
  // Get channel, waiting for reconnection if necessary
  const channel = await getPersistentChannel();

  // Publish with confirm callback for reliable delivery
  return await publishWithConfirm(channel, exchangeName, routingKey, message);
};
// endregion

export const rabbitmqConnectionConfig = () => {
  return {
    host: HOSTNAME,
    vhost: VHOST,
    use_ssl: USE_SSL,
    port: PORT,
    user: USERNAME,
    pass: PASSWORD,
  };
};

const amqpHttpClient = async () => {
  const ssl = USE_SSL_MGMT ? 's' : '';
  const baseURL = `http${ssl}://${HOSTNAME_MGMT}:${PORT_MGMT}`;
  const httpClientOptions = {
    baseURL,
    responseType: 'json',
    rejectUnauthorized: RABBITMQ_MGMT_REJECT_UNAUTHORIZED,
    auth: {
      username: USERNAME,
      password: PASSWORD,
    },
  };
  return getHttpClient(httpClientOptions);
};

/**
 * Purge listen and push queue when connector state is reset using rabbit HTTP api management.
 * @param connector All information concerning a specific connector
 */
export const purgeConnectorQueues = async (connector) => {
  const httpClient = await amqpHttpClient();
  const pathPushQueue = `/api/queues${isEmptyField(VHOST_PATH) ? '/%2F' : VHOST_PATH}/${RABBITMQ_PUSH_QUEUE_PREFIX}${connector.id}/contents`;
  const pathListenQueue = `/api/queues${isEmptyField(VHOST_PATH) ? '/%2F' : VHOST_PATH}/${RABBITMQ_LISTEN_QUEUE_PREFIX}${connector.id}/contents`;

  await httpClient.delete(pathPushQueue).then((response) => response.data);
  await httpClient.delete(pathListenQueue).then((response) => response.data);
};

export const getConnectorQueueDetails = async (connectorId) => {
  try {
    const httpClient = await amqpHttpClient();
    const pathRabbit = `/api/queues${isEmptyField(VHOST_PATH) ? '/%2F' : VHOST_PATH}/${RABBITMQ_PUSH_QUEUE_PREFIX}${connectorId}`;

    const queueDetailResponse = await httpClient.get(pathRabbit).then((response) => response.data);
    logApp.debug('Rabbit HTTP API response', { queueDetailResponse });
    return {
      messages_number: queueDetailResponse.messages || 0,
      messages_size: queueDetailResponse.message_bytes || 0,
    };
  } catch (e) {
    // For managed connector, the queue is available only after the connector is started.
    logApp.warn('Get connector queue details fail', { cause: e, connectorId });
    return {
      messages_number: 0,
      messages_size: 0,
    };
  }
};

const amqpExecute = async (execute) => {
  const connOptions = getConnectionOptions();
  return new Promise((resolve, reject) => {
    try {
      amqp.connect(amqpUri(), connOptions, (err, conn) => {
        if (err) {
          reject(err);
        } else { // Connection success
          conn.on('error', (onConnectError) => {
            logApp.error('Rabbit Error trying to connect', { onConnectError });
            reject(onConnectError);
          });
          conn.createConfirmChannel((channelError, channel) => {
            if (channelError) {
              logApp.error('Rabbit Error on channel', { channelError });
              reject(channelError);
            } else {
              channel.on('error', (onChannelError) => {
                logApp.error('Rabbit Error on channel', { onChannelError });
                reject(onChannelError);
              });
              execute(channel).then((data) => {
                channel.close();
                conn.close();
                resolve(data);
              }).catch((executeError) => {
                logApp.error('Rabbit Error on execute', { executeError });
                reject(executeError);
              });
            }
          });
        }
      });
    } catch (globalError) {
      logApp.error('Rabbit Error', { globalError });
      reject(globalError);
    }
  });
};

/**
 * Send a message using the persistent connection for high performance
 *
 * Guarantees:
 * - At-least-once delivery with retries on failure
 * - Blocking reconnection: waits for RabbitMQ recovery if connection lost
 * - Backpressure: respects channel buffer limits
 *
 * Note: Ordering is maintained when callers use sequential awaits.
 * In rare edge cases around connection failures, duplicate delivery
 * is possible (at-least-once semantics). Consumers should be idempotent.
 */
export const send = async (exchangeName, routingKey, message) => {
  const MAX_SEND_RETRIES = 3;
  let lastError = null;

  for (let attempt = 1; attempt <= MAX_SEND_RETRIES; attempt += 1) {
    try {
      return await sendPersistent(exchangeName, routingKey, message);
    } catch (err) {
      lastError = err;
      logApp.warn(`[RABBITMQ] Send failed (attempt ${attempt}/${MAX_SEND_RETRIES})`, { cause: err });

      // If channel was lost, wait for reconnection before retry
      if (!persistentChannel) {
        logApp.info('[RABBITMQ] Waiting for connection recovery before retry...');
        await getPersistentChannel();
      }
    }
  }

  // All retries exhausted
  throw lastError;
};

export const metrics = async (context, user) => {
  const metricApi = async () => {
    const httpClient = await amqpHttpClient();
    const overview = await httpClient.get('/api/overview').then((response) => response.data);
    const queues = await httpClient.get(`/api/queues${VHOST_PATH}`).then((response) => response.data);
    // Compute number of push queues
    const platformQueues = queues.filter((q) => q.name.startsWith(RABBIT_QUEUE_PREFIX));
    const pushQueues = platformQueues.filter((q) => q.name.startsWith(`${RABBIT_QUEUE_PREFIX}push_`) && q.consumers > 0);
    const consumers = pushQueues.length > 0 ? pushQueues[0].consumers : 0;
    return { overview, consumers, queues: platformQueues };
  };
  return telemetry(context, user, 'QUEUE metrics', {
    [SEMATTRS_DB_NAME]: 'messaging_engine',
    [SEMATTRS_DB_OPERATION]: 'metrics',
  }, metricApi);
};

const metricsCache = new LRUCache({ ttl: 15000, max: 1 }); // 15 seconds cache
export const getConnectorQueueSize = async (context, user, connectorId) => {
  let stats = metricsCache.get('cached_metrics');
  if (!stats) {
    stats = await metrics(context, user);
    metricsCache.set('cached_metrics', stats);
  }
  const targetQueues = stats.queues.filter((queue) => queue.name.includes(connectorId));
  return targetQueues.length > 0 ? targetQueues.reduce((a, b) => (a.messages ?? 0) + (b.messages ?? 0)) : 0;
};
export const getBestBackgroundConnectorId = async (context, user) => {
  let stats = metricsCache.get('cached_metrics');
  if (!stats) {
    stats = await metrics(context, user);
    metricsCache.set('cached_metrics', stats);
  }
  // Find the least used push queue
  const targetQueues = stats.queues.filter((queue) => queue.name.startsWith(`${RABBIT_QUEUE_PREFIX}push_background-task`));
  const bestQueue = targetQueues.sort((a, b) => (a.messages ?? 0) - (b.messages ?? 0))[0];
  return bestQueue.name.substring(`${RABBIT_QUEUE_PREFIX}push_`.length);
};

export const listenRouting = (connectorId) => `${RABBIT_QUEUE_PREFIX}listen_routing_${connectorId}`;
export const pushRouting = (connectorId) => `${RABBIT_QUEUE_PREFIX}push_routing_${connectorId}`;

// Dead letter queue routing ID for bundles that are too large.
// NOTE:
// - This constant is used here to build the dead_letter_routing value in connectorConfig.
// - The full CONNECTOR_QUEUE_BUNDLES_TOO_LARGE queue configuration object is defined later
//   in this file near the rest of the queue declarations.
const CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID = 'too-large-bundle';

/**
 * Build the complete connector configuration that includes:
 * - RabbitMQ connection info
 * - S3 connection info
 * - Queue routing configuration
 */
export const connectorConfig = (id, listen_callback_uri = undefined) => ({
  connection: rabbitmqConnectionConfig(),
  s3: s3ConnectionConfig(),
  push: `${RABBIT_QUEUE_PREFIX}push_${id}`,
  push_routing: pushRouting(id),
  push_exchange: WORKER_EXCHANGE,
  listen: `${RABBIT_QUEUE_PREFIX}listen_${id}`,
  listen_routing: listenRouting(id),
  listen_exchange: CONNECTOR_EXCHANGE,
  listen_callback_uri,
  dead_letter_routing: listenRouting(CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID),
});

export const registerConnectorQueues = async (id, name, type, scope) => {
  const listenQueue = `${RABBIT_QUEUE_PREFIX}listen_${id}`;
  const pushQueue = `${RABBIT_QUEUE_PREFIX}push_${id}`;
  await amqpExecute(async (channel) => {
    // 01. Ensure exchange exists
    const assertExchange = util.promisify(channel.assertExchange).bind(channel);
    await assertExchange(CONNECTOR_EXCHANGE, 'direct', { durable: true });
    await assertExchange(WORKER_EXCHANGE, 'direct', { durable: true });
    // 02. Ensure listen queue exists
    const assertQueue = util.promisify(channel.assertQueue).bind(channel);
    await assertQueue(listenQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: { name, config: { id, type, scope }, 'x-queue-type': QUEUE_TYPE },
    });
    // 03. bind queue for each connector scope
    const bindQueue = util.promisify(channel.bindQueue).bind(channel);
    await bindQueue(listenQueue, CONNECTOR_EXCHANGE, listenRouting(id), {});
    // 04. Create stix push queue
    await assertQueue(pushQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: { name, config: { id, type, scope }, 'x-queue-type': QUEUE_TYPE },
    });
    // 05. Bind push queue to direct default exchange
    await bindQueue(pushQueue, WORKER_EXCHANGE, pushRouting(id), {});
    return true;
  });
  return connectorConfig(id);
};

export const getInternalBackgroundTaskQueues = () => {
  const backgroundTaskConnectorQueues = [];
  for (let i = 0; i < BACKGROUND_TASK_QUEUES; i += 1) {
    backgroundTaskConnectorQueues.push(
      { id: `background-task-${i}`, name: `[TASK] Internal task processing #${i}`, type: 'internal', scope: ENTITY_TYPE_BACKGROUND_TASK },
    );
  }
  return backgroundTaskConnectorQueues;
};
// region deprecated fixed queues
// we have now dedicated queues for each playbook and each sync (see getInternalPlaybookQueues & getInternalSyncQueues)
const CONNECTOR_QUEUE_PLAYBOOK = { id: 'playbook', name: 'Internal playbook manager', type: 'internal', scope: 'playbook' };
const CONNECTOR_QUEUE_SYNC = { id: 'sync', name: 'Internal sync manager', type: 'internal', scope: 'sync' };
/** @deprecated [>=6.3 & <6.6]. Remove and add migration to remove the queues. */
const DEPRECATED_INTERNAL_QUEUES = [CONNECTOR_QUEUE_PLAYBOOK, CONNECTOR_QUEUE_SYNC];
const CONNECTOR_QUEUE_BUNDLES_TOO_LARGE = { id: 'too-large-bundle', name: 'Bundle too large for ingestion', type: 'internal', scope: 'dead letter' };
// endregion
export const getInternalQueues = () => {
  const backgroundTaskConnectorQueues = getInternalBackgroundTaskQueues();
  return [CONNECTOR_QUEUE_BUNDLES_TOO_LARGE, ...DEPRECATED_INTERNAL_QUEUES, ...backgroundTaskConnectorQueues];
};

export const initializeInternalQueues = async () => {
  const internalQueues = getInternalQueues();
  for (let i = 0; i < internalQueues.length; i += 1) {
    const internalQueue = internalQueues[i];
    await registerConnectorQueues(internalQueue.id, internalQueue.name, internalQueue.type, internalQueue.scope);
  }
};

export const getInternalPlaybookQueues = async (context, user) => {
  const playbookQueues = [];
  const playbooks = await fullEntitiesList(context, user, [ENTITY_TYPE_PLAYBOOK]);
  for (let index = 0; index < playbooks.length; index += 1) {
    const playbook = playbooks[index];
    playbookQueues.push({ id: playbook.internal_id, name: `[PLAYBOOK] ${playbook.name}`, type: 'internal', scope: ENTITY_TYPE_PLAYBOOK });
  }
  return playbookQueues;
};

export const getInternalSyncQueues = async (context, user) => {
  const syncQueues = [];
  const syncs = await fullEntitiesList(context, user, [ENTITY_TYPE_SYNC]);
  for (let index = 0; index < syncs.length; index += 1) {
    const sync = syncs[index];
    syncQueues.push({ id: sync.internal_id, name: `[SYNC] ${sync.name}`, type: 'internal', scope: ENTITY_TYPE_SYNC });
  }
  return syncQueues;
};

// This method reinitialize the expected queues in rabbitmq
// Thanks to this approach if rabbitmq is destroyed, restarting the platform
// will recreate everything needed by the queuing system.
export const enforceQueuesConsistency = async (context, user) => {
  // List all current platform connectors and ensure queues are correctly setup
  const connectors = await fullEntitiesList(context, user, [ENTITY_TYPE_CONNECTOR]);
  for (let index = 0; index < connectors.length; index += 1) {
    const connector = connectors[index];
    const scopes = connector.connector_scope ? connector.connector_scope.split(',') : [];
    await registerConnectorQueues(connector.internal_id, connector.name, connector.connector_type, scopes);
  }
  // List all current platform playbooks and ensure queues are correctly setup
  const playbooksQueues = await getInternalPlaybookQueues(context, user);
  for (let index = 0; index < playbooksQueues.length; index += 1) {
    const playbookQueue = playbooksQueues[index];
    await registerConnectorQueues(playbookQueue.id, playbookQueue.name, playbookQueue.type, playbookQueue.scope);
  }
  // List all current platform synchronizers (OpenCTI Streams) and ensure queues are correctly setup
  const syncQueues = await getInternalSyncQueues(context, user);
  for (let i = 0; i < syncQueues.length; i += 1) {
    const syncQueue = syncQueues[i];
    await registerConnectorQueues(syncQueue.id, syncQueue.name, syncQueue.type, syncQueue.scope);
  }
};

export const unregisterConnector = async (id) => {
  const listen = await amqpExecute(async (channel) => {
    const deleteQueue = util.promisify(channel.deleteQueue).bind(channel);
    return deleteQueue(`${RABBIT_QUEUE_PREFIX}listen_${id}`, {});
  });
  const push = await amqpExecute(async (channel) => {
    const deleteQueue = util.promisify(channel.deleteQueue).bind(channel);
    return deleteQueue(`${RABBIT_QUEUE_PREFIX}push_${id}`, {});
  });
  return { listen, push };
};

export const unregisterExchanges = async () => {
  await amqpExecute(async (channel) => {
    const deleteExchange = util.promisify(channel.deleteExchange).bind(channel);
    return deleteExchange(CONNECTOR_EXCHANGE, {});
  });
  await amqpExecute(async (channel) => {
    const deleteExchange = util.promisify(channel.deleteExchange).bind(channel);
    return deleteExchange(WORKER_EXCHANGE, {});
  });
};

export const rabbitMQIsAlive = async () => {
  return amqpExecute(async (channel) => {
    const assertExchange = util.promisify(channel.assertExchange).bind(channel);
    return assertExchange(CONNECTOR_EXCHANGE, 'direct', { durable: true });
  }).catch(
    /* v8 ignore next */ (e) => {
      throw DatabaseError('RabbitMQ seems down', { cause: e });
    },
  );
};

export const pushToWorkerForConnector = (connectorId, message) => {
  const routingKey = pushRouting(connectorId);
  return send(WORKER_EXCHANGE, routingKey, JSON.stringify(message));
};

export const pushToConnector = (connectorId, message) => {
  return send(CONNECTOR_EXCHANGE, listenRouting(connectorId), JSON.stringify(message));
};

export const getRabbitMQVersion = (context) => {
  return metrics(context, SYSTEM_USER)
    .then((data) => data.overview.rabbitmq_version)
    .catch(/* v8 ignore next */ () => 'Disconnected');
};

export const consumeQueue = async (context, connectorId, connectionSetterCallback, callback) => {
  const cfg = connectorConfig(connectorId);
  const listenQueue = cfg.listen;
  const connOptions = getConnectionOptions();
  return new Promise((_, reject) => {
    try {
      amqp.connect(amqpUri(), connOptions, (err, conn) => {
        if (err) {
          reject(err);
        } else { // Connection success
          logApp.debug('[QUEUEING] Starting connector queue consuming', { connectorId });
          conn.on('close', (onConnectError) => {
            if (onConnectError) {
              reject(onConnectError);
            }
          });
          conn.on('error', (onConnectError) => {
            reject(onConnectError);
          });
          connectionSetterCallback(conn);
          conn.createChannel((channelError, channel) => {
            if (channelError) {
              reject(channelError);
            } else {
              channel.on('error', (onChannelError) => {
                reject(onChannelError);
              });
              channel.consume(listenQueue, (data) => {
                if (data !== null) {
                  callback(context, data.content.toString());
                }
              }, { noAck: true }, (consumeError) => {
                if (consumeError) {
                  logApp.error('[QUEUEING] Consumption fail', {
                    connectorId,
                    cause: consumeError,
                  });
                }
              });
            }
          });
        }
      });
    } catch (globalError) {
      reject(globalError);
    }
  });
};
