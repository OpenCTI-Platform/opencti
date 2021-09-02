import {
  connectorDelete,
  connectorForWork,
  connectors,
  connectorsForExport,
  connectorsForImport,
  loadConnectorById,
  pingConnector,
  registerConnector,
  resetStateConnector,
} from '../domain/connector';
import {
  createWork,
  deleteWork,
  reportActionImport,
  updateProcessedTime,
  updateReceivedTime,
  worksForConnector,
  findAll,
  findById,
} from '../domain/work';
import { findById as findUserById } from '../domain/user';
import { redisGetWork, redisUpdateActionExpectation } from '../database/redis';
import { now } from '../utils/format';

const connectorResolvers = {
  Query: {
    connector: (_, { id }, { user }) => loadConnectorById(user, id),
    connectors: (_, __, { user }) => connectors(user),
    connectorsForExport: (_, __, { user }) => connectorsForExport(user),
    connectorsForImport: (_, __, { user }) => connectorsForImport(user),
    works: (_, args, { user }) => findAll(user, args),
    work: (_, { id }, { user }) => findById(user, id),
  },
  Connector: {
    connector_user: (connector, _, { user }) => findUserById(user, connector.connector_user_id),
    works: (connector, args, { user }) => worksForConnector(connector.id, user, args),
  },
  Work: {
    connector: (work, _, { user }) => connectorForWork(user, work.id),
    user: (work, _, { user }) => findUserById(user, work.user_id),
    tracking: (work) => redisGetWork(work.id),
  },
  Mutation: {
    deleteConnector: (_, { id }, { user }) => connectorDelete(user, id),
    registerConnector: (_, { input }, { user }) => registerConnector(user, input),
    resetStateConnector: (_, { id }, { user }) => resetStateConnector(user, id),
    pingConnector: (_, { id, state }, { user }) => pingConnector(user, id, state),
    // Work part
    workAdd: async (_, { connectorId, friendlyName }, { user }) => {
      const connector = await loadConnectorById(user, connectorId);
      return createWork(user, connector, friendlyName, connector.id, { receivedTime: now() });
    },
    workEdit: (_, { id }, { user }) => ({
      delete: () => deleteWork(user, id),
      reportExpectation: ({ error }) => reportActionImport(user, id, error),
      addExpectations: ({ expectations }) => redisUpdateActionExpectation(user, id, expectations),
      toReceived: ({ message }) => updateReceivedTime(user, id, message),
      toProcessed: ({ message, inError }) => updateProcessedTime(user, id, message, inError),
    }),
  },
};

export default connectorResolvers;
