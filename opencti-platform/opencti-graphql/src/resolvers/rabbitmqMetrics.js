import { getMetrics } from '../domain/rabbitmqMetrics';

const rabbitmqMetricsResolvers = {
  Query: {
    rabbitMQMetrics: (_, args, context) => getMetrics(context, context.user, args),
  },
};

export default rabbitmqMetricsResolvers;
