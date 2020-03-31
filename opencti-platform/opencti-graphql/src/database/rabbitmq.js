import amqp from 'amqplib';
import axios from 'axios';
import { filter, includes, pipe, map, reduce, add, divide } from 'ramda';
import conf from '../config/conf';

export const CONNECTOR_EXCHANGE = 'amqp.connector.exchange';
export const WORKER_EXCHANGE = 'amqp.worker.exchange';

const amqpUri = () => {
  const user = conf.get('rabbitmq:username');
  const pass = conf.get('rabbitmq:password');
  const host = conf.get('rabbitmq:hostname');
  const port = conf.get('rabbitmq:port');
  return `amqp://${user}:${pass}@${host}:${port}`;
};

const amqpExecute = (execute) => {
  return new Promise((resolve, reject) => {
    amqp
      .connect(amqpUri())
      .then((connection) => {
        return connection
          .createConfirmChannel()
          .then((channel) => {
            return execute(channel)
              .then((response) => {
                channel.close();
                connection.close();
                resolve(response);
                return true;
              })
              .catch((e) => reject(e));
          })
          .catch((e) => reject(e));
      })
      .catch((e) => reject(e));
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
          {}, // No option
          (err, ok) => {
            if (err) reject(err);
            resolve(ok);
          }
        );
      })
  );
};

export const metrics = async () => {
  const baseURL = `http${conf.get('rabbitmq:management_ssl') === true ? 's' : ''}://${conf.get(
    'rabbitmq:hostname'
  )}:${conf.get('rabbitmq:port_management')}`;
  const overview = await axios
    .get('/api/overview', {
      baseURL,
      withCredentials: true,
      auth: {
        username: conf.get('rabbitmq:username'),
        password: conf.get('rabbitmq:password'),
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
        username: conf.get('rabbitmq:username'),
        password: conf.get('rabbitmq:password'),
      },
    })
    .then((response) => {
      return response.data;
    });
  // Compute number of push queues
  const pushQueues = filter((q) => includes('push_', q.name), queues);
  const nbPushQueues = pushQueues.length;
  const nbConsumers = pipe(
    map((q) => q.consumers),
    reduce(add, 0)
  )(pushQueues);
  let finalCount = 0;
  if (nbConsumers > 0 && nbPushQueues > 0) {
    // Because worker connect to every queue.
    finalCount = divide(nbConsumers, nbPushQueues);
  }
  return { overview, consumers: Math.round(finalCount), queues };
};

export const connectorConfig = (id) => ({
  uri: amqpUri(),
  push: `push_${id}`,
  push_exchange: 'amqp.worker.exchange',
  listen: `listen_${id}`,
  listen_exchange: 'amqp.connector.exchange',
});

export const listenRouting = (connectorId) => `listen_routing_${connectorId}`;

export const pushRouting = (connectorId) => `push_routing_${connectorId}`;

export const registerConnectorQueues = async (id, name, type, scope) => {
  // 01. Ensure exchange exists
  await amqpExecute((channel) =>
    channel.assertExchange(CONNECTOR_EXCHANGE, 'direct', {
      durable: true,
    })
  );
  await amqpExecute((channel) =>
    channel.assertExchange(WORKER_EXCHANGE, 'direct', {
      durable: true,
    })
  );

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
  await amqpExecute(c =>
    c.bindQueue(listenQueue, CONNECTOR_EXCHANGE, listenRouting(id))
  );

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

export const pushToConnector = (connector, message) => {
  return send(CONNECTOR_EXCHANGE, listenRouting(connector.internal_id_key), JSON.stringify(message));
};

export const getRabbitMQVersion = () => {
  return metrics()
    .then((data) => data.overview.rabbitmq_version)
    .catch(() => 'Disconnected');
};
