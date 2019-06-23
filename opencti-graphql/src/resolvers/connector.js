import { getConnectors, updateConfig } from '../domain/connector';

const connectorResolvers = {
  Query: {
    connectors: () => getConnectors()
  },
  Mutation: {
    connectorConfig: (_, { identifier, config }) =>
      updateConfig(identifier, config)
  }
};

export default connectorResolvers;
