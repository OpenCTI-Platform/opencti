import { readFileSync } from 'node:fs';
import amqp from 'amqplib';
import axios from 'axios';
import * as R from 'ramda';
import conf, { booleanConf, configureCA } from '../config/conf';
import { DatabaseError, UnknownError } from '../config/errors';

export const INTERNAL_SYNC_QUEUE = 'sync';
export const CONNECTOR_EXCHANGE = 'amqp.connector.exchange';
export const WORKER_EXCHANGE = 'amqp.worker.exchange';

export const EVENT_TYPE_DEPENDENCIES = 'init-dependencies';
export const EVENT_TYPE_INIT = 'init-create';

export const EVENT_TYPE_CREATE = 'create';
export const EVENT_TYPE_UPDATE = 'update';
export const EVENT_TYPE_MERGE = 'merge';
export const EVENT_TYPE_DELETE = 'delete';

const USE_SSL = booleanConf('rabbitmq:use_ssl', false);
const QUEUE_TYPE = conf.get('rabbitmq:queue_type');
const RABBITMQ_CA = conf.get('rabbitmq:ca').map((path) => readFileSync(path));
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

export const config = () => {
  return {
    host: HOSTNAME,
    vhost: VHOST,
    use_ssl: USE_SSL,
    port: PORT,
    user: USERNAME,
    pass: PASSWORD,
  };
};

const amqpExecute = async (execute) => {
  try {
    const amqpConnection = await amqp.connect(amqpUri(), USE_SSL ? {
      ...amqpCred(),
      tls: {
        ...configureCA(RABBITMQ_CA),
        servername: HOSTNAME,
      }
    } : amqpCred());
    const channel = await amqpConnection.createConfirmChannel();
    const response = await execute(channel);
    await channel.close();
    await amqpConnection.close();
    return response;
  } catch (err) {
    throw UnknownError('Error in amqp command execution', { error: err });
  }
};

// { deliveryMode: 2 } = persistent message
export const send = (exchangeName, routingKey, message) => {
  return amqpExecute((channel) => channel.publish(exchangeName, routingKey, Buffer.from(message), { deliveryMode: 2 }));
};

export const metrics = async () => {
  const ssl = USE_SSL_MGMT ? 's' : '';
  const baseURL = `http${ssl}://${HOSTNAME_MGMT}:${PORT_MGMT}`;

  const overview = await axios
    .get('/api/overview', {
      baseURL,
      withCredentials: true,
      auth: {
        username: USERNAME,
        password: PASSWORD,
      },
    })
    .then((response) => {
      return response.data;
    });
  const queues = await axios
    .get(`/api/queues${VHOST_PATH}`, {
      baseURL,
      withCredentials: true,
      auth: {
        username: USERNAME,
        password: PASSWORD,
      },
    })
    .then((response) => {
      return response.data;
    });
  // Compute number of push queues
  const pushQueues = R.filter((q) => R.includes('push_', q.name) && q.consumers > 0, queues);
  const consumers = R.head(pushQueues) ? R.head(pushQueues).consumers : 0;
  return { overview, consumers, queues };
};

export const connectorConfig = (id) => ({
  connection: config(),
  push: `push_${id}`,
  push_exchange: 'amqp.worker.exchange',
  listen: `listen_${id}`,
  listen_exchange: 'amqp.connector.exchange',
});

export const listenRouting = (connectorId) => `listen_routing_${connectorId}`;

export const pushRouting = (connectorId) => `push_routing_${connectorId}`;

export const registerConnectorQueues = async (id, name, type, scope) => {
  const listenQueue = `listen_${id}`;
  const pushQueue = `push_${id}`;
  await amqpExecute(async (channel) => {
    // 01. Ensure exchange exists
    await channel.assertExchange(CONNECTOR_EXCHANGE, 'direct', { durable: true });
    await channel.assertExchange(WORKER_EXCHANGE, 'direct', { durable: true });
    // 02. Ensure listen queue exists
    await channel.assertQueue(listenQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: { name, config: { id, type, scope }, 'x-queue-type': QUEUE_TYPE },
    });
    // 03. bind queue for each connector scope
    await channel.bindQueue(listenQueue, CONNECTOR_EXCHANGE, listenRouting(id));
    // 04. Create stix push queue
    await channel.assertQueue(pushQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: { name, config: { id, type, scope }, 'x-queue-type': QUEUE_TYPE },
    });
    // 05. Bind push queue to direct default exchange
    await channel.bindQueue(pushQueue, WORKER_EXCHANGE, pushRouting(id));
  });
  return connectorConfig(id);
};

export const unregisterConnector = async (id) => {
  const listen = await amqpExecute((channel) => channel.deleteQueue(`listen_${id}`));
  const push = await amqpExecute((channel) => channel.deleteQueue(`push_${id}`));
  return { listen, push };
};

export const rabbitMQIsAlive = async () => {
  // 01. Ensure exchange exists
  await amqpExecute((channel) => channel.assertExchange(CONNECTOR_EXCHANGE, 'direct', {
    durable: true,
  })).catch(
    /* istanbul ignore next */ (e) => {
      throw DatabaseError('RabbitMQ seems down', { error: e.message });
    }
  );
  // 02. Ensure sync queue exists
  await registerConnectorQueues(INTERNAL_SYNC_QUEUE, 'Internal sync manager', 'internal', 'sync');
};

export const pushToSync = (message) => {
  return send(WORKER_EXCHANGE, pushRouting('sync'), JSON.stringify(message));
};

export const pushToConnector = (connector, message) => {
  return send(CONNECTOR_EXCHANGE, listenRouting(connector.internal_id), JSON.stringify(message));
};

export const getRabbitMQVersion = () => {
  return metrics()
    .then((data) => data.overview.rabbitmq_version)
    .catch(/* istanbul ignore next */ () => 'Disconnected');
};
