import amqp from 'amqplib';
import axios from 'axios';
import { map } from 'ramda';
import conf, { logger } from '../config/conf';

const amqpUri = () => {
  const user = conf.get('rabbitmq:username');
  const pass = conf.get('rabbitmq:password');
  const host = conf.get('rabbitmq:hostname');
  const port = conf.get('rabbitmq:port');
  return `amqp://${user}:${pass}@${host}:${port}`;
};

const amqpExecute = execute => {
  return new Promise((resolve, reject) => {
    amqp
      .connect(amqpUri())
      .then(connection => {
        return connection
          .createChannel()
          .then(channel => {
            execute(channel)
              .then(response => {
                channel.close();
                connection.close();
                resolve(response);
              })
              .catch(e => reject(e));
          })
          .catch(e => reject(e));
      })
      .catch(e => reject(e));
  });
};

export const send = (exchangeName, routingKey, message) => {
  if (exchangeName && routingKey && message) {
    amqp
      .connect(
        `amqp://${conf.get('rabbitmq:username')}:${conf.get(
          'rabbitmq:password'
        )}@${conf.get('rabbitmq:hostname')}:${conf.get('rabbitmq:port')}`
      )
      .then(connection => {
        return connection.createChannel().then(channel => {
          logger.debug(
            `[RABBITMQ] Sending ${message} to ${exchangeName} - ${routingKey}`
          );
          return channel
            .assertExchange(exchangeName, 'direct', { durable: true })
            .then(() => {
              channel.publish(exchangeName, routingKey, Buffer.from(message));
              setTimeout(() => {
                connection.close();
              }, 5000);
            });
        });
      });
  }
};

export const metrics = async () => {
  const baseURL = `http${
    conf.get('rabbitmq:management_ssl') === true ? 's' : ''
  }://${conf.get('rabbitmq:hostname')}:${conf.get('rabbitmq:port_management')}`;
  const overview = await axios
    .get('/api/overview', {
      baseURL,
      withCredentials: true,
      auth: {
        username: conf.get('rabbitmq:username'),
        password: conf.get('rabbitmq:password')
      }
    })
    .then(response => {
      return response.data;
    });
  const queues = await axios
    .get('/api/queues', {
      baseURL,
      withCredentials: true,
      auth: {
        username: conf.get('rabbitmq:username'),
        password: conf.get('rabbitmq:password')
      }
    })
    .then(response => {
      return response.data;
    });
  return { overview, queues };
};

export const connectorConfig = id => ({
  uri: amqpUri(),
  listen: `listen_${id}`,
  push: `push_${id}`
});

export const registerConnectorQueues = async (id, type, scope) => {
  // 01. Ensure exchange exists
  const connectorExchangeTopic = 'amqp.connector.exchange';
  await amqpExecute(channel =>
    channel.assertExchange(connectorExchangeTopic, 'direct', {
      durable: true
    })
  );
  const workerExchangeTopic = 'amqp.worker.exchange';
  await amqpExecute(channel =>
    channel.assertExchange(workerExchangeTopic, 'direct', {
      durable: true
    })
  );

  // 02. Ensure listen queue exists
  const listenQueue = `listen_${id}`;
  await amqpExecute(channel =>
    channel.assertQueue(listenQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: {
        config: { id, type, scope }
      }
    })
  );

  // 03. bind queue for the each connector scope
  // eslint-disable-next-line prettier/prettier
  await Promise.all(map(s => amqpExecute(channel => channel.bindQueue(
      listenQueue, connectorExchangeTopic, `${type}-${s}`)), scope));

  // 04. Create stix push queue
  const pushQueue = `push_${id}`;
  await amqpExecute(channel =>
    channel.assertQueue(pushQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: {
        config: { id, type, scope }
      }
    })
  );

  // 05. Bind push queue to direct default exchange
  await amqpExecute(channel =>
    channel.bindQueue(pushQueue, workerExchangeTopic, id)
  );

  return connectorConfig(id);
};
