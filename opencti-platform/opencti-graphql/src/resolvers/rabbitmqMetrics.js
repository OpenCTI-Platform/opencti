import { getMetrics } from '../domain/rabbitmqMetrics';

const rabbitmqMetricsResolvers = {
  Query: {
    rabbitMQMetrics: (_, args) => getMetrics(args),
  },
};

export default rabbitmqMetricsResolvers;
