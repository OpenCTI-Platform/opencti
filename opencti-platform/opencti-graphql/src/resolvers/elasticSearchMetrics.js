import { getMetrics } from '../domain/elasticSearchMetrics';

const elasticSearchMetricsResolvers = {
  Query: {
    elasticSearchMetrics: () => getMetrics(),
  },
};

export default elasticSearchMetricsResolvers;
