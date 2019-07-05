import amqp from 'amqplib';
import axios from 'axios';
import conf, { logger } from '../config/conf';

export const send = (exchangeName, key, message) => {
  if (exchangeName && key && message) {
    amqp
      .connect(
        `amqp://${conf.get('rabbitmq:username')}:${conf.get(
          'rabbitmq:password'
        )}@${conf.get('rabbitmq:hostname')}:${conf.get('rabbitmq:port')}`
      )
      .then(connection => {
        return connection.createChannel().then(channel => {
          logger.debug(
            `[RABBITMQ] Sending ${message} to ${exchangeName} - ${key}`
          );
          return channel
            .assertExchange(exchangeName, 'topic', { durable: true })
            .then(() => {
              channel.publish(exchangeName, key, Buffer.from(message));
              setTimeout(() => {
                connection.close();
              }, 5000);
            });
        });
      });
  }
};

export const statsQueues = () => {
  const baseURL = `http${
    conf.get('rabbitmq:management_ssl') === true ? 's' : ''
  }://${conf.get('rabbitmq:hostname')}:${conf.get('rabbitmq:port_management')}`;
  return axios
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
};
