import {
  connectorDelete,
  connectors,
  connectorsForExport,
  connectorsForImport,
  loadConnectorById,
  pingConnector,
  registerConnector,
  resetStateConnector,
} from '../domain/connector';
import {
  connectorForWork,
  createWork,
  deleteWork,
  reportActionImport,
  updateProcessedTime,
  updateReceivedTime,
  worksForConnector,
  findAll,
} from '../domain/work';
import { findById as findUserById } from '../domain/user';
import { redisGetWork, redisUpdateActionExpectation } from '../database/redis';
import { now } from '../utils/format';

const connectorResolvers = {
  Query: {
    connector: (_, { id }) => loadConnectorById(id),
    connectors: () => connectors(),
    connectorsForExport: () => connectorsForExport(),
    connectorsForImport: () => connectorsForImport(),
    works: (_, args) => findAll(args),
  },
  Connector: {
    connector_user: (connector) => findUserById(connector.connector_user_id),
    works: (connector, args) => worksForConnector(connector.id, args),
  },
  Work: {
    connector: (work) => connectorForWork(work.id),
    user: (work) => findUserById(work.user_id),
    tracking: (work) => redisGetWork(work.id),
  },
  Mutation: {
    deleteConnector: (_, { id }, { user }) => connectorDelete(user, id),
    registerConnector: (_, { input }, { user }) => registerConnector(user, input),
    resetStateConnector: (_, { id }, { user }) => resetStateConnector(user, id),
    pingConnector: (_, { id, state }, { user }) => pingConnector(user, id, state),
    // Work part
    workAdd: async (_, { connectorId, friendlyName }, { user }) => {
      const connector = await loadConnectorById(connectorId);
      return createWork(user, connector, friendlyName, connector.id, { receivedTime: now() });
    },
    workEdit: (_, { id }, { user }) => ({
      delete: () => deleteWork(id),
      reportExpectation: ({ error }) => reportActionImport(user, id, error),
      addExpectations: ({ expectations }) => redisUpdateActionExpectation(user, id, expectations),
      toReceived: ({ message }) => updateReceivedTime(user, id, message),
      toProcessed: ({ message, inError }) => updateProcessedTime(user, id, message, inError),
    }),
  },
};

export default connectorResolvers;
