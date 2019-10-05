import {
  connectors,
  registerConnector,
  pingConnector,
  connectorsForExport
} from '../domain/connector';
import { deleteById, sinceNowInMinutes } from '../database/grakn';
import { reportJobError } from '../domain/work';

const connectorResolvers = {
  Query: {
    connectors: () => connectors(),
    connectorsForExport: () => connectorsForExport()
  },
  Connector: {
    active: connector => sinceNowInMinutes(connector.updated_at) < 2
  },
  Mutation: {
    registerConnector: (_, { input }) => registerConnector(input),
    pingConnector: (_, { id }) => pingConnector(id),
    reportJobError: (_, { id, message }) => reportJobError(id, message),
    resetJob: (_, { id }) => deleteById(id)
  }
};

export default connectorResolvers;
