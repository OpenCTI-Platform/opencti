import { readFileSync } from 'fs';
import amqp from 'amqplib';
import axios from 'axios';
import * as R from 'ramda';
import conf, { booleanConf, configureCA } from '../config/conf';
import { DatabaseError } from '../config/errors';

export const CONNECTOR_EXCHANGE = 'amqp.connector.exchange';
export const WORKER_EXCHANGE = 'amqp.worker.exchange';

export const EVENT_TYPE_SYNC = 'sync';
export const EVENT_TYPE_CREATE = 'create';
export const EVENT_TYPE_UPDATE = 'update';
export const EVENT_TYPE_MERGE = 'merge';
export const EVENT_TYPE_DELETE = 'delete';

const USE_SSL = booleanConf('amqp:use_ssl', false);
const AMQP_CA = conf.get('amqp:ca').map((path) => readFileSync(path));

const amqpUri = () => {
  const host = conf.get('amqp:hostname');
  const port = conf.get('amqp:port');
  return `amqp${USE_SSL ? 's' : ''}://${host}:${port}`;
};

const amqpCred = () => {
  const user = conf.get('amqp:username');
  const pass = conf.get('amqp:password');
  return { credentials: amqp.credentials.plain(user, pass) };
};

export const config = () => {
  return {
    host: conf.get('amqp:hostname'),
    use_ssl: booleanConf('amqp:use_ssl', false),
    port: conf.get('amqp:port'),
    user: conf.get('amqp:username'),
    pass: conf.get('amqp:password'),
  };
};

const amqpExecute = (execute) => {
  return new Promise((resolve, reject) => {
    amqp
      .connect(amqpUri(), USE_SSL ? { ...amqpCred(), ...configureCA(AMQP_CA) } : amqpCred())
      .then((connection) => {
        return connection
          .createConfirmChannel()
          .then((channel) => {
            const commandExecution = execute(channel);
            return commandExecution
              .then((response) => {
                channel.close();
                connection.close();
                resolve(response);
                return true;
              })
              .catch(/* istanbul ignore next */ (e) => reject(e));
          })
          .catch(/* istanbul ignore next */ (e) => reject(e));
      })
      .catch(/* istanbul ignore next */ (e) => reject(e));
  });
};

export const send = (exchangeName, routingKey, message) => {
  return amqpExecute(
    (channel) =>
      new Promise((resolve, reject) => {
        channel.publish(
          exchangeName,
          routingKey,
          Buffer.from(message),
          { deliveryMode: 2 }, // Make message persistent
          (err, ok) => {
            if (err) reject(err);
            resolve(ok);
          }
        );
      })
  );
};

export const metrics = async () => {
  const baseURL = `http${conf.get('amqp:management_ssl') === true ? 's' : ''}://${conf.get('amqp:hostname')}:${conf.get(
    'amqp:port_management'
  )}`;
  const overview = await axios
    .get('/api/overview', {
      baseURL,
      withCredentials: true,
      auth: {
        username: conf.get('amqp:username'),
        password: conf.get('amqp:password'),
      },
    })
    .then((response) => {
      return response.data;
    });
  const queues = await axios
    .get('/api/queues', {
      baseURL,
      withCredentials: true,
      auth: {
        username: conf.get('amqp:username'),
        password: conf.get('amqp:password'),
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
  // 01. Ensure exchange exists
  await amqpExecute((channel) => channel.assertExchange(CONNECTOR_EXCHANGE, 'direct', { durable: true }));
  await amqpExecute((channel) => channel.assertExchange(WORKER_EXCHANGE, 'direct', { durable: true }));
  // 02. Ensure listen queue exists
  const listenQueue = `listen_${id}`;
  await amqpExecute((channel) =>
    channel.assertQueue(listenQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: {
        name,
        config: { id, type, scope },
      },
    })
  );
  // 03. bind queue for the each connector scope
  // eslint-disable-next-line prettier/prettier
  await amqpExecute((c) => c.bindQueue(listenQueue, CONNECTOR_EXCHANGE, listenRouting(id)));
  // 04. Create stix push queue
  const pushQueue = `push_${id}`;
  await amqpExecute((channel) =>
    channel.assertQueue(pushQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: {
        name,
        config: { id, type, scope },
      },
    })
  );
  // 05. Bind push queue to direct default exchange
  await amqpExecute((channel) => channel.bindQueue(pushQueue, WORKER_EXCHANGE, pushRouting(id)));
  return connectorConfig(id);
};

export const unregisterConnector = async (id) => {
  const listen = await amqpExecute((channel) => channel.deleteQueue(`listen_${id}`));
  const push = await amqpExecute((channel) => channel.deleteQueue(`push_${id}`));
  return { listen, push };
};

export const amqpIsAlive = async () => {
  // 01. Ensure exchange exists
  await amqpExecute((channel) =>
    channel.assertExchange(CONNECTOR_EXCHANGE, 'direct', {
      durable: true,
    })
  ).catch(
    /* istanbul ignore next */ (e) => {
      throw DatabaseError('amqp seems down', { error: e.message });
    }
  );
};

export const pushToConnector = (connector, message) => {
  return send(CONNECTOR_EXCHANGE, listenRouting(connector.internal_id), JSON.stringify(message));
};

export const getAMQPVersion = () => {
  return metrics()
    .then((data) => data.overview.amqp_version)
    .catch(/* istanbul ignore next */ () => 'Disconnected');
};
