import { getMetrics } from '../domain/elasticSearchMetrics';

const elasticSearchMetricsResolvers = {
  Query: {
    elasticSearchMetrics: (_, args) => getMetrics(args),
  },
};

export default elasticSearchMetricsResolvers;
