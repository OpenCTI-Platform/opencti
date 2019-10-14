import {
  connectors,
  registerConnector,
  pingConnector,
  connectorsForExport,
  connectorsForImport
} from '../domain/connector';
import { deleteById } from '../database/grakn';
import { loadConnectorForWork, reportJobStatus } from '../domain/work';

const connectorResolvers = {
  Query: {
    connectors: () => connectors(),
    connectorsForExport: () => connectorsForExport(),
    connectorsForImport: () => connectorsForImport()
  },
  Work: {
    connector: work => loadConnectorForWork(work.id)
  },
  Mutation: {
    registerConnector: (_, { input }) => registerConnector(input),
    pingConnector: (_, { id }) => pingConnector(id),
    reportJobStatus: (_, { id, status, message }) =>
      reportJobStatus(id, status, message),
    resetJob: (_, { id }) => deleteById(id)
  }
};

export default connectorResolvers;
