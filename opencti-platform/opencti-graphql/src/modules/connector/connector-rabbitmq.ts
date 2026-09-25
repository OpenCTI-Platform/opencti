import amqp from 'amqplib/callback_api';
import util from 'util';
import { isEmptyField, RABBIT_QUEUE_PREFIX } from '../../database/utils';
import {
  executeRabbitmq,
  getCachedRabbitmqMetrics,
  rabbitmqConnectionConfig,
  rabbitmqConnectionOptions,
  rabbitmqManagementClient,
  rabbitmqUri,
  rabbitmqVhostPath,
  sendRabbitmq,
  WORKER_EXCHANGE,
} from '../../database/rabbitmq';
import { s3ConnectionConfig } from '../../database/raw-file-storage';
import { fullEntitiesList } from '../../database/middleware-loader';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC } from '../../schema/internalObject';
import { ENTITY_TYPE_PLAYBOOK } from '../playbook/playbook-types';
import type { BasicStoreEntityConnector } from './connector-types';
import type { AuthContext, AuthUser } from '../../types/user';
import conf, { logApp } from '../../config/conf';
import { DatabaseError } from '../../config/errors';

export const CONNECTOR_EXCHANGE = `${RABBIT_QUEUE_PREFIX}amqp.connector.exchange`;

interface RabbitmqQueueMetric {
  name: string;
  messages?: number;
  consumers?: number;
}

const RABBITMQ_PUSH_QUEUE_PREFIX = `${RABBIT_QUEUE_PREFIX}push_`;
const RABBITMQ_LISTEN_QUEUE_PREFIX = `${RABBIT_QUEUE_PREFIX}listen_`;
const CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID = 'too-large-bundle';
export const BACKGROUND_TASK_QUEUES = parseInt(conf.get('app:task_scheduler:max_queues_breakdown') ?? '4', 10);

const listenRouting = (connectorId: string) => `${RABBIT_QUEUE_PREFIX}listen_routing_${connectorId}`;
const pushRouting = (connectorId: string) => `${RABBIT_QUEUE_PREFIX}push_routing_${connectorId}`;

export const connectorConfig = (id: string, listen_callback_uri: string | undefined = undefined) => ({
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

export const purgeConnectorQueues = async (connector: { id: string }) => {
  const httpClient = await rabbitmqManagementClient();
  const vhostPath = isEmptyField(rabbitmqVhostPath) ? '/%2F' : rabbitmqVhostPath;
  await httpClient.delete(`/api/queues${vhostPath}/${RABBITMQ_PUSH_QUEUE_PREFIX}${connector.id}/contents`).then((response: any) => response.data);
  await httpClient.delete(`/api/queues${vhostPath}/${RABBITMQ_LISTEN_QUEUE_PREFIX}${connector.id}/contents`).then((response: any) => response.data);
};

export const getConnectorQueueDetails = async (connectorId: string) => {
  try {
    const httpClient = await rabbitmqManagementClient();
    const vhostPath = isEmptyField(rabbitmqVhostPath) ? '/%2F' : rabbitmqVhostPath;
    const [pushResult, listenResult] = await Promise.all([
      httpClient.get(`/api/queues${vhostPath}/${RABBITMQ_PUSH_QUEUE_PREFIX}${connectorId}`).then((response: any) => response.data).catch(() => null),
      httpClient.get(`/api/queues${vhostPath}/${RABBITMQ_LISTEN_QUEUE_PREFIX}${connectorId}`).then((response: any) => response.data).catch(() => null),
    ]);
    logApp.debug('Rabbit HTTP API response', { pushResult, listenResult });
    return {
      messages_number: (pushResult?.messages ?? 0) + (listenResult?.messages ?? 0),
      messages_size: (pushResult?.message_bytes ?? 0) + (listenResult?.message_bytes ?? 0),
    };
  } catch (error) {
    logApp.warn('Get connector queue details fail', { cause: error, connectorId });
    return { messages_number: 0, messages_size: 0 };
  }
};

export const getConnectorQueueSize = async (context: AuthContext, user: AuthUser, connectorId: string) => {
  const stats = await getCachedRabbitmqMetrics(context, user) as { queues: RabbitmqQueueMetric[] };
  const targetQueues = stats.queues.filter((queue) => queue.name.includes(connectorId));
  return targetQueues.reduce((total, queue) => total + (queue.messages ?? 0), 0);
};

export const registerConnectorQueues = async (id: string, name: string, type: string, scope: string | string[] | null | undefined) => {
  const listenQueue = `${RABBIT_QUEUE_PREFIX}listen_${id}`;
  const pushQueue = `${RABBIT_QUEUE_PREFIX}push_${id}`;
  await executeRabbitmq(async (channel: any) => {
    const assertExchange = util.promisify(channel.assertExchange).bind(channel);
    await assertExchange(CONNECTOR_EXCHANGE, 'direct', { durable: true });
    await assertExchange(WORKER_EXCHANGE, 'direct', { durable: true });
    const assertQueue = util.promisify(channel.assertQueue).bind(channel);
    const arguments_ = { name, config: { id, type, scope }, 'x-queue-type': conf.get('rabbitmq:queue_type') };
    await assertQueue(listenQueue, { exclusive: false, durable: true, autoDelete: false, arguments: arguments_ });
    const bindQueue = util.promisify(channel.bindQueue).bind(channel);
    await bindQueue(listenQueue, CONNECTOR_EXCHANGE, listenRouting(id), {});
    await assertQueue(pushQueue, { exclusive: false, durable: true, autoDelete: false, arguments: arguments_ });
    await bindQueue(pushQueue, WORKER_EXCHANGE, pushRouting(id), {});
    return true;
  });
  return connectorConfig(id);
};

export const unregisterConnector = async (id: string) => {
  const deleteQueue = async (queue: string) => executeRabbitmq(async (channel: any) => {
    return util.promisify(channel.deleteQueue).bind(channel)(queue, {});
  });
  const [listen, push] = await Promise.all([
    deleteQueue(`${RABBIT_QUEUE_PREFIX}listen_${id}`),
    deleteQueue(`${RABBIT_QUEUE_PREFIX}push_${id}`),
  ]);
  return { listen, push };
};

export const unregisterExchanges = async () => {
  await executeRabbitmq(async (channel: any) => util.promisify(channel.deleteExchange).bind(channel)(CONNECTOR_EXCHANGE, {}));
  await executeRabbitmq(async (channel: any) => util.promisify(channel.deleteExchange).bind(channel)(WORKER_EXCHANGE, {}));
};

export const rabbitMQIsAlive = async () => {
  return executeRabbitmq(async (channel: any) => {
    return util.promisify(channel.assertExchange).bind(channel)(CONNECTOR_EXCHANGE, 'direct', { durable: true });
  }).catch((error) => {
    throw DatabaseError('RabbitMQ seems down', { cause: error });
  });
};

export const rabbitMQInit = async () => {
  logApp.info('[CHECK] Checking if RabbitMq is available');
  await rabbitMQIsAlive();
  logApp.info('[CHECK] RabbitMq is alive');
  return true;
};

export const getInternalBackgroundTaskQueues = () => {
  return Array.from({ length: BACKGROUND_TASK_QUEUES }, (_, index) => ({
    id: `background-task-${index}`,
    name: `[TASK] Internal task processing #${index}`,
    type: 'internal',
    scope: ENTITY_TYPE_BACKGROUND_TASK,
  }));
};

const DEPRECATED_INTERNAL_QUEUES = [
  { id: 'playbook', name: 'Internal playbook manager', type: 'internal', scope: 'playbook' },
  { id: 'sync', name: 'Internal sync manager', type: 'internal', scope: 'sync' },
];
const CONNECTOR_QUEUE_BUNDLES_TOO_LARGE = { id: CONNECTOR_QUEUE_BUNDLES_TOO_LARGE_ID, name: 'Bundle too large for ingestion', type: 'internal', scope: 'dead letter' };

export const getInternalQueues = () => [
  CONNECTOR_QUEUE_BUNDLES_TOO_LARGE,
  ...DEPRECATED_INTERNAL_QUEUES,
  ...getInternalBackgroundTaskQueues(),
];

export const initializeInternalQueues = async () => {
  for (const queue of getInternalQueues()) {
    await registerConnectorQueues(queue.id, queue.name, queue.type, queue.scope);
  }
};

export const getInternalPlaybookQueues = async (context: AuthContext, user: AuthUser) => {
  const playbooks = await fullEntitiesList(context, user, [ENTITY_TYPE_PLAYBOOK]);
  return playbooks.map((playbook) => ({
    id: playbook.internal_id, name: `[PLAYBOOK] ${playbook.name}`, type: 'internal', scope: ENTITY_TYPE_PLAYBOOK,
  }));
};

export const getInternalSyncQueues = async (context: AuthContext, user: AuthUser) => {
  const syncs = await fullEntitiesList(context, user, [ENTITY_TYPE_SYNC]);
  return syncs.map((sync) => ({
    id: sync.internal_id, name: `[SYNC] ${sync.name}`, type: 'internal', scope: ENTITY_TYPE_SYNC,
  }));
};

export const enforceQueuesConsistency = async (context: AuthContext, user: AuthUser) => {
  const connectors = await fullEntitiesList<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR]);
  for (const connector of connectors) {
    await registerConnectorQueues(
      connector.internal_id,
      connector.name,
      connector.connector_type,
      connector.connector_scope ? connector.connector_scope.split(',') : [],
    );
  }
  const internalQueues = [
    ...await getInternalPlaybookQueues(context, user),
    ...await getInternalSyncQueues(context, user),
  ];
  for (const queue of internalQueues) {
    await registerConnectorQueues(queue.id, queue.name, queue.type, queue.scope);
  }
};

export const pushToConnector = (connectorId: string, message: unknown) => {
  return sendRabbitmq(CONNECTOR_EXCHANGE, listenRouting(connectorId), JSON.stringify(message));
};

export const consumeQueue = async (
  context: AuthContext,
  connectorId: string,
  connectionSetterCallback: (connection: any) => void,
  callback: (context: AuthContext, message: string) => void,
) => {
  const listenQueue = connectorConfig(connectorId).listen;
  return new Promise((_, reject) => {
    try {
      amqp.connect(rabbitmqUri(), rabbitmqConnectionOptions(), (error: Error | null, connection: any) => {
        if (error) {
          reject(error);
          return;
        }
        logApp.debug('[QUEUEING] Starting connector queue consuming', { connectorId });
        connection.on('close', (connectionError: Error | undefined) => connectionError && reject(connectionError));
        connection.on('error', (connectionError: Error) => reject(connectionError));
        connectionSetterCallback(connection);
        connection.createChannel((channelError: Error | null, channel: any) => {
          if (channelError) {
            reject(channelError);
            return;
          }
          channel.on('error', (channelConnectionError: Error) => reject(channelConnectionError));
          channel.consume(listenQueue, (data: any) => {
            if (data !== null) {
              callback(context, data.content.toString());
            }
          }, { noAck: true }, (consumeError: Error | null) => {
            if (consumeError) {
              logApp.error('[QUEUEING] Consumption fail', { connectorId, cause: consumeError });
            }
          });
        });
      });
    } catch (error) {
      reject(error);
    }
  });
};
