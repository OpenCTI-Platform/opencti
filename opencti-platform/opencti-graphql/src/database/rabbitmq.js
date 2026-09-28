import amqp from 'amqplib/callback_api';
import { ATTR_DB_NAMESPACE, ATTR_DB_OPERATION_NAME, SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import { LRUCache } from 'lru-cache';
import conf, { booleanConf, configureCA, loadCert, logApp } from '../config/conf';
import { DatabaseError } from '../config/errors';
import { SYSTEM_USER } from '../utils/access';
import { telemetry } from '../config/tracing';
import { RABBIT_QUEUE_PREFIX, wait, toBase64, fromBase64 } from './utils';
import { getHttpClient } from '../utils/http-client';
import { Stix2Splitter } from '../utils/stix2-splitter';
import { updateExpectationsNumber } from '../domain/work';

export const WORKER_EXCHANGE = `${RABBIT_QUEUE_PREFIX}amqp.worker.exchange`;

const USE_SSL = booleanConf('rabbitmq:use_ssl', false);
const readFileFromConfig = (configKey) => (conf.get(configKey) ? loadCert(conf.get(configKey)) : undefined);
const RABBITMQ_CA = (conf.get('rabbitmq:use_ssl_ca') ?? []).map((path) => loadCert(path));
const RABBITMQ_CA_CERT = readFileFromConfig('rabbitmq:use_ssl_cert');
const RABBITMQ_CA_KEY = readFileFromConfig('rabbitmq:use_ssl_key');
const RABBITMQ_CA_PFX = readFileFromConfig('rabbitmq:use_ssl_pfx');
const RABBITMQ_CA_PASSPHRASE = conf.get('rabbitmq:use_ssl_passphrase');
const RABBITMQ_REJECT_UNAUTHORIZED = booleanConf('rabbitmq:use_ssl_reject_unauthorized', false);
const RABBITMQ_MGMT_REJECT_UNAUTHORIZED = booleanConf('rabbitmq:management_ssl_reject_unauthorized', false);
const HOSTNAME = conf.get('rabbitmq:hostname');
const PORT = conf.get('rabbitmq:port');
const USERNAME = conf.get('rabbitmq:username');
const PASSWORD = conf.get('rabbitmq:password');
const VHOST = conf.get('rabbitmq:vhost');
export const rabbitmqVhostPath = VHOST === '/' ? '' : `/${VHOST}`;
const USE_SSL_MGMT = booleanConf('rabbitmq:management_ssl', false);
const HOSTNAME_MGMT = conf.get('rabbitmq:hostname_management') || HOSTNAME;
const PORT_MGMT = conf.get('rabbitmq:port_management');

export const rabbitmqUri = () => {
  const ssl = USE_SSL ? 's' : '';
  return `amqp${ssl}://${HOSTNAME}:${PORT}${rabbitmqVhostPath}`;
};

const amqpCred = () => {
  return { credentials: amqp.credentials.plain(USERNAME, PASSWORD) };
};

export const rabbitmqConnectionOptions = () => {
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
    const connOptions = rabbitmqConnectionOptions();
    amqp.connect(rabbitmqUri(), connOptions, (err, conn) => {
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
      // Channel might have been closed between getting it and publishing.
      // Do not reset persistentChannel here: the channel 'error'/'close' handlers
      // are the single source of truth that invalidate it and trigger a clean
      // reconnection. Nulling it here (without closing the connection) races with
      // those handlers and can leave the publisher stuck retrying on a zombie state.
      // Just reject so the caller can retry.
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

export const rabbitmqManagementClient = async () => {
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

export const executeRabbitmq = async (execute) => {
  const connectionOptions = rabbitmqConnectionOptions();
  return new Promise((resolve, reject) => {
    try {
      amqp.connect(rabbitmqUri(), connectionOptions, (connectionError, connection) => {
        if (connectionError) {
          reject(connectionError);
          return;
        }
        connection.on('error', (error) => {
          logApp.error('Rabbit Error trying to connect', { error });
          reject(error);
        });
        connection.createConfirmChannel((channelError, channel) => {
          if (channelError) {
            logApp.error('Rabbit Error on channel', { channelError });
            reject(channelError);
            return;
          }
          channel.on('error', (error) => {
            logApp.error('Rabbit Error on channel', { error });
            reject(error);
          });
          execute(channel)
            .then((data) => {
              channel.close();
              connection.close();
              resolve(data);
            })
            .catch((error) => {
              logApp.error('Rabbit Error on execute', { error });
              reject(error);
            });
        });
      });
    } catch (error) {
      logApp.error('Rabbit Error', { error });
      reject(error);
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
 *
 * Not exported on purpose: callers must go through a queue-specific publisher.
 */
export const sendRabbitmq = async (exchangeName, routingKey, message) => {
  let attemptNumber = 0;
  let retryDelay = RECONNECT_INITIAL_DELAY;

  while (true) {
    try {
      return await sendPersistent(exchangeName, routingKey, message);
    } catch (err) {
      logApp.warn(`[RABBITMQ] Send failed (attempt ${++attemptNumber}), retrying in ${retryDelay}ms`, { cause: err, exchangeName, routingKey });

      // If channel was lost, wait for reconnection before retry
      if (!persistentChannel) {
        logApp.info('[RABBITMQ] Waiting for connection recovery before retry...');
        await getPersistentChannel();
      }

      // Wait with exponential backoff before retrying
      await wait(retryDelay);
      retryDelay = Math.min(retryDelay * RECONNECT_MULTIPLIER, RECONNECT_MAX_DELAY);
    }
  }
};

export const metrics = async (context, user) => {
  const metricApi = async () => {
    const httpClient = await rabbitmqManagementClient();
    const overview = await httpClient.get('/api/overview', { timeout: 5000 }).then((response) => response.data);
    const queues = await httpClient.get(`/api/queues${rabbitmqVhostPath}`, { timeout: 5000 }).then((response) => response.data);
    // Compute number of push queues
    const platformQueues = queues.filter((q) => q.name.startsWith(RABBIT_QUEUE_PREFIX));
    const pushQueues = platformQueues.filter((q) => q.name.startsWith(`${RABBIT_QUEUE_PREFIX}push_`) && q.consumers > 0);
    const consumers = pushQueues.length > 0 ? pushQueues[0].consumers : 0;
    return { overview, consumers, queues: platformQueues };
  };
  return telemetry(context, user, 'QUEUE metrics', {
    [ATTR_DB_NAMESPACE]: 'messaging_engine',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_NAME]: 'messaging_engine',
    [ATTR_DB_OPERATION_NAME]: 'metrics',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_OPERATION]: 'metrics',
  }, metricApi);
};

const metricsCache = new LRUCache({ ttl: 15000, max: 1 }); // 15 seconds cache
export const getCachedRabbitmqMetrics = async (context, user) => {
  let stats = metricsCache.get('cached_metrics');
  if (!stats) {
    stats = await metrics(context, user);
    metricsCache.set('cached_metrics', stats);
  }
  return stats;
};

export const UNKNOWN_CONNECTOR_TYPE = 'UNKNOWN';

// Consumers are reported per connector type rather than aggregated, so callers own
// the capacity model they derive from them (ingestion units, saturation ratios...).
export const getQueueConsumersByType = async (context, user) => {
  let stats = metricsCache.get('cached_metrics');
  if (!stats) {
    stats = await metrics(context, user);
    metricsCache.set('cached_metrics', stats);
  }
  const queues = Array.isArray(stats?.queues) ? stats.queues : [];
  return queues
    .filter((queue) => (queue?.name ?? '').startsWith(`${RABBIT_QUEUE_PREFIX}push_`))
    .reduce((consumersByType, queue) => {
      const connectorType = queue?.arguments?.config?.type ?? UNKNOWN_CONNECTOR_TYPE;
      consumersByType[connectorType] = (consumersByType[connectorType] ?? 0) + (queue?.consumers ?? 0);
      return consumersByType;
    }, {});
};
export const getBestBackgroundConnectorId = async (context, user) => {
  const stats = await getCachedRabbitmqMetrics(context, user);
  // Find the least used push queue
  const targetQueues = stats.queues.filter((queue) => queue.name.startsWith(`${RABBIT_QUEUE_PREFIX}push_background-task`));
  const bestQueue = targetQueues.sort((a, b) => (a.messages ?? 0) - (b.messages ?? 0))[0];
  return bestQueue.name.substring(`${RABBIT_QUEUE_PREFIX}push_`.length);
};

/**
 * Pure splitting decision for an outgoing worker message.
 * Returns { messages, expectations }:
 * - messages: the message(s) to actually publish. The original message, unchanged, when the
 *   splitter never runs (not a bundle, already flagged no_split, or the bundle only has a single
 *   object pre-split); otherwise one message per bundle produced by the splitter (which may be
 *   fewer than the raw object count once duplicates/incompatible items are removed, including
 *   down to a single message or none at all).
 * - expectations: the total number of STIX objects the bundle represents, used by
 *   pushBundleToWorker to keep the work's expected completion count in sync. null when the
 *   message isn't a STIX bundle at all (e.g. sync 'event' messages), since those don't carry
 *   expectation semantics here.
 */
export const buildSplitMessages = (message) => {
  const unsplit = (expectations) => ({ messages: [message], expectations });
  if (message.type !== 'bundle') {
    return unsplit(null);
  }
  const bundleContent = fromBase64(message.content);
  let parsedBundle;
  try {
    parsedBundle = JSON.parse(bundleContent);
  } catch (e) {
    throw DatabaseError('Invalid stix bundle content', { cause: e });
  }
  const objectCount = Array.isArray(parsedBundle.objects) ? parsedBundle.objects.length : 0;
  // Mirror the worker's own pre-check (push_handler.py): never attempt to split single-object
  // (or explicitly no_split) bundles. This avoids needless work for the common case and sidesteps
  // the splitter's dependency-walk on payloads it was never meant to touch (matching prior
  // behavior exactly, since single-object bundles were never split by the worker either).
  if (message.no_split || objectCount <= 1) {
    return unsplit(objectCount);
  }
  // Once the splitter has run, its output (deduped/filtered) is authoritative for both the
  // messages to publish and the expectation count - including the 0- and 1-bundle cases, which
  // can differ from the raw objectCount when the bundle contains duplicate ids or incompatible
  // items. Always flagging no_split: true here also prevents the worker from re-splitting (and
  // re-adding expectations for) content we already split.
  const splitter = new Stix2Splitter();
  const { bundles, numberExpectations } = splitter.splitBundleWithExpectations(bundleContent);
  const messages = bundles.map((bundle) => ({ ...message, content: toBase64(bundle), no_split: true }));
  return { messages, expectations: numberExpectations };
};

/**
 * Publishes a message to a connector's worker queue.
 * Whenever message.work_id is set, the work's expected completion count is incremented by the
 * actual number of STIX objects being sent - whether the bundle ends up split into several
 * messages or sent as a single one. Tracking is additive (Redis HINCRBY), so this is safe to do
 * unconditionally: every caller's objects are new work for that work_id, never a resend of an
 * already-counted total.
 */
export const pushBundleToWorker = async (context, user, connectorId, message) => {
  const routingKey = `${RABBIT_QUEUE_PREFIX}push_routing_${connectorId}`;
  const { messages, expectations } = buildSplitMessages(message);
  if (message.type === 'bundle') {
    logApp.debug('[WORKER] Bundle split into queue messages', { connectorId, work_id: message.work_id, messageCount: messages.length, expectations });
  }
  const shouldTrackExpectations = message.work_id && context && user && expectations > 0;
  if (shouldTrackExpectations) {
    await updateExpectationsNumber(context, user, message.work_id, expectations);
  }
  for (const splitMessage of messages) {
    await sendRabbitmq(WORKER_EXCHANGE, routingKey, JSON.stringify(splitMessage));
  }
};

export const getRabbitMQVersion = (context) => {
  return metrics(context, SYSTEM_USER)
    .then((data) => data.overview.rabbitmq_version)
    .catch(/* v8 ignore next */ () => 'Disconnected');
};
