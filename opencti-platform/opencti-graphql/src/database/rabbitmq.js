import amqp from 'amqplib';
import axios from 'axios';
import conf, { logger } from '../config/conf';

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
