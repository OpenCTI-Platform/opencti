import { getMetrics, getIndexMetrics } from '../domain/searchMetrics';

const elasticSearchMetricsResolvers = {
  Query: {
    elasticSearchMetrics: () => getMetrics(),
    dataIndexMetrics: () => getIndexMetrics(),
  },
};

export default elasticSearchMetricsResolvers;
