import { getMetrics } from '../domain/queue';

const connectorResolvers = {
  Query: {
    queuesMetrics: (_, args) => getMetrics(args)
  },
};

export default connectorResolvers;
