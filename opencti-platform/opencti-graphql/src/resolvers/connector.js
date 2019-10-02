import {
  connectors,
  registerConnector,
  pingConnector,
  connectorsForExport
} from '../domain/connector';

const connectorResolvers = {
  Query: {
    connectors: () => connectors(),
    connectorsForExport: () => connectorsForExport()
  },
  Mutation: {
    registerConnector: (_, { input }) => registerConnector(input),
    pingConnector: (_, { id }) => pingConnector(id)
  }
};

export default connectorResolvers;
