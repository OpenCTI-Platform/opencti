import { getMetrics } from '../domain/amqpMetrics';

const amqpMetricsResolvers = {
  Query: {
    amqpMetrics: (_, args) => getMetrics(args),
  },
};

export default amqpMetricsResolvers;
