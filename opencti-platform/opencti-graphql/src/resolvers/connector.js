import { getConnectors, updateConfig, getStatistics } from '../domain/connector';

const connectorResolvers = {
  Query: {
    connectors: () => getConnectors(),
    connectorsStats: () => getStatistics()
  },
  Mutation: {
    connectorConfig: (_, { identifier, config }) =>
      updateConfig(identifier, config)
  }
};

export default connectorResolvers;
