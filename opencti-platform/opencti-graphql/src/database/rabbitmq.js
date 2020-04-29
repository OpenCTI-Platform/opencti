import amqp from 'amqplib';
import axios from 'axios';
import { add, divide, filter, includes, map, pipe, reduce } from 'ramda';
import { v4 as uuid } from 'uuid';
import conf, { logger } from '../config/conf';
import { generateLogMessage, utcDate } from './utils';
import { convertDataToStix } from './stix';

export const CONNECTOR_EXCHANGE = 'amqp.connector.exchange';
export const WORKER_EXCHANGE = 'amqp.worker.exchange';
export const LOGS_EXCHANGE = 'amqp.logs.exchange';

export const EVENT_TYPE_CREATE = 'create';
export const EVENT_TYPE_UPDATE = 'update';
export const EVENT_TYPE_UPDATE_ADD = 'update_add';
export const EVENT_TYPE_UPDATE_REMOVE = 'update_remove';
export const EVENT_TYPE_DELETE = 'delete';

export const amqpUri = () => {
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
  /* istanbul ignore if */
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

export const ensureRabbitMQAndLogsQueue = async () => {
  // 01. Ensure exchange exists
  await amqpExecute((channel) =>
    channel.assertExchange(LOGS_EXCHANGE, 'topic', {
      durable: true,
    })
  ).catch(
    /* istanbul ignore next */ () => {
      logger.error(`[RABBITMQ] Seems down`);
      throw new Error('RabbitMQ seems down');
    }
  );
  // 02. Ensure logs queue exists
  const listenQueue = 'logs_all';
  await amqpExecute((channel) =>
    channel.assertQueue(listenQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: {
        name: 'OpenCTI logs queue',
      },
    })
  ).catch(
    /* istanbul ignore next */ () => {
      logger.error(`[RABBITMQ] Seems down`);
      throw new Error('RabbitMQ seems down');
    }
  );
  // 03. bind queue for the each connector scope
  // eslint-disable-next-line prettier/prettier
  await amqpExecute((c) => c.bindQueue(listenQueue, LOGS_EXCHANGE, 'community.*'));
};

export const pushToConnector = (connector, message) => {
  return send(CONNECTOR_EXCHANGE, listenRouting(connector.internal_id_key), JSON.stringify(message));
};

export const pushToLogs = (communityId, message) => {
  return send(LOGS_EXCHANGE, `community.${communityId}`, JSON.stringify(message));
};

export const getRabbitMQVersion = () => {
  return metrics()
    .then((data) => data.overview.rabbitmq_version)
    .catch(/* istanbul ignore next */ () => 'Disconnected');
};

export const sendLog = async (eventType, eventUser, eventData, eventExtraData = null) => {
  const finalEventData = await convertDataToStix(eventData, eventType, eventExtraData);
  const message = {
    event_type: eventType,
    event_user: eventUser.id,
    event_date: utcDate().toISOString(),
    event_data: finalEventData,
    event_message: generateLogMessage(eventType, eventUser, eventData, eventExtraData),
  };
  // TODO @Sam
  // Here we need to parse the data and send to all declared communities that match the data
  const communityId = uuid();
  const communities = [communityId];
  await Promise.all(communities.map((community) => pushToLogs(community, message)));
};
