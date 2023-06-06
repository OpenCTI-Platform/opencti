import amqp from 'amqplib';
import axios from 'axios';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { Agent } from 'node:https';
import conf, { booleanConf, configureCA, loadCert } from '../config/conf';
import { DatabaseError, UnknownError } from '../config/errors';
import { SYSTEM_USER } from '../utils/access';
import { telemetry } from '../config/tracing';
import { RABBIT_QUEUE_PREFIX } from './utils';

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
      ...configureCA(RABBITMQ_CA),
      cert: RABBITMQ_CA_CERT,
      key: RABBITMQ_CA_KEY,
      pfx: RABBITMQ_CA_PFX,
      passphrase: RABBITMQ_CA_PASSPHRASE,
      rejectUnauthorized: RABBITMQ_REJECT_UNAUTHORIZED,
      // checkServerIdentity: () => undefined,
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

export const send = (exchangeName, routingKey, message) => {
  return amqpExecute((channel) => channel.publish(exchangeName, routingKey, Buffer.from(message), { deliveryMode: 2 }));
};

export const metrics = async (context, user) => {
  const metricApi = async () => {
    const ssl = USE_SSL_MGMT ? 's' : '';
    const baseURL = `http${ssl}://${HOSTNAME_MGMT}:${PORT_MGMT}`;
    const httpsAgent = ssl ? new Agent({ rejectUnauthorized: RABBITMQ_MGMT_REJECT_UNAUTHORIZED }) : undefined;
    const axiosConfig = {
      baseURL,
      httpsAgent,
      withCredentials: true,
      auth: {
        username: USERNAME,
        password: PASSWORD,
      },
    };
    const overview = await axios.get('/api/overview', axiosConfig).then((response) => response.data);
    const queues = await axios.get(`/api/queues${VHOST_PATH}`, axiosConfig).then((response) => response.data);
    // Compute number of push queues
    const platformQueues = queues.filter((q) => q.name.startsWith(RABBIT_QUEUE_PREFIX));
    const pushQueues = platformQueues.filter((q) => q.name.startsWith(`${RABBIT_QUEUE_PREFIX}push_`) && q.consumers > 0);
    const consumers = pushQueues.length > 0 ? pushQueues[0].consumers : 0;
    return { overview, consumers, queues: platformQueues };
  };
  return telemetry(context, user, 'QUEUE metrics', {
    [SemanticAttributes.DB_NAME]: 'messaging_engine',
    [SemanticAttributes.DB_OPERATION]: 'metrics',
  }, metricApi);
};

export const connectorConfig = (id) => ({
  connection: config(),
  push: `${RABBIT_QUEUE_PREFIX}push_${id}`,
  push_routing: pushRouting(id),
  push_exchange: WORKER_EXCHANGE,
  listen: `${RABBIT_QUEUE_PREFIX}listen_${id}`,
  listen_routing: listenRouting(id),
  listen_exchange: CONNECTOR_EXCHANGE,
});

export const listenRouting = (connectorId) => `${RABBIT_QUEUE_PREFIX}listen_routing_${connectorId}`;

export const pushRouting = (connectorId) => `${RABBIT_QUEUE_PREFIX}push_routing_${connectorId}`;

export const registerConnectorQueues = async (id, name, type, scope) => {
  const listenQueue = `${RABBIT_QUEUE_PREFIX}listen_${id}`;
  const pushQueue = `${RABBIT_QUEUE_PREFIX}push_${id}`;
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
  const listen = await amqpExecute((channel) => channel.deleteQueue(`${RABBIT_QUEUE_PREFIX}listen_${id}`));
  const push = await amqpExecute((channel) => channel.deleteQueue(`${RABBIT_QUEUE_PREFIX}push_${id}`));
  return { listen, push };
};

export const unregisterExchanges = async () => {
  await amqpExecute((channel) => channel.deleteExchange(CONNECTOR_EXCHANGE));
  await amqpExecute((channel) => channel.deleteExchange(WORKER_EXCHANGE));
};

export const rabbitMQIsAlive = async () => {
  await amqpExecute((channel) => channel.assertExchange(CONNECTOR_EXCHANGE, 'direct', {
    durable: true,
  })).catch(
    /* istanbul ignore next */ (e) => {
      throw DatabaseError('RabbitMQ seems down', { error: e.data });
    }
  );
};

export const pushToSync = (message) => {
  return send(WORKER_EXCHANGE, pushRouting('sync'), JSON.stringify(message));
};

export const pushToConnector = (context, connector, message) => {
  return send(CONNECTOR_EXCHANGE, listenRouting(connector.internal_id), JSON.stringify(message));
};

export const getRabbitMQVersion = (context) => {
  return metrics(context, SYSTEM_USER)
    .then((data) => data.overview.rabbitmq_version)
    .catch(/* istanbul ignore next */ () => 'Disconnected');
};
