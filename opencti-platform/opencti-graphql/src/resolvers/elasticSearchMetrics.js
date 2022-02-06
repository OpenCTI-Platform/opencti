import { getMetrics } from '../domain/searchMetrics';

const elasticSearchMetricsResolvers = {
  Query: {
    elasticSearchMetrics: () => getMetrics(),
  },
};

export default elasticSearchMetricsResolvers;
