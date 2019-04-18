import amqp from 'amqplib';
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
