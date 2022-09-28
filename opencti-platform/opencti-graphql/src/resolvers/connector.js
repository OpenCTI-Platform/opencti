import {
  connectorDelete,
  connectorForWork,
  connectorsForExport,
  findAllSync,
  loadConnectorById,
  patchSync,
  pingConnector,
  registerConnector,
  registerSync,
  resetStateConnector,
  testSync,
  syncDelete,
  syncCleanContext,
  syncEditContext,
  syncEditField,
  findSyncById,
} from '../domain/connector';
import {
  createWork,
  deleteWork,
  reportExpectation,
  updateProcessedTime,
  updateReceivedTime,
  worksForConnector,
  findAll,
  findById,
  deleteWorkForConnector,
  pingWork, updateExpectationsNumber,
} from '../domain/work';
import { findById as findUserById } from '../domain/user';
import { redisGetWork } from '../database/redis';
import { now } from '../utils/format';
import { connectors, connectorsForImport, connectorsForWorker } from '../database/repository';

const connectorResolvers = {
  Query: {
    connector: (_, { id }, { user }) => loadConnectorById(user, id),
    connectors: (_, __, { user }) => connectors(user),
    connectorsForWorker: (_, __, { user }) => connectorsForWorker(user),
    connectorsForExport: (_, __, { user }) => connectorsForExport(user),
    connectorsForImport: (_, __, { user }) => connectorsForImport(user),
    works: (_, args, { user }) => findAll(user, args),
    work: (_, { id }, { user }) => findById(user, id),
    synchronizer: (_, { id }, { user }) => findSyncById(user, id),
    synchronizers: (_, args, { user }) => findAllSync(user, args),
  },
  Connector: {
    works: (connector, args, { user }) => worksForConnector(user, connector.id, args),
  },
  Work: {
    connector: (work, _, { user }) => connectorForWork(user, work.id),
    user: (work, _, { user }) => findUserById(user, work.user_id),
    tracking: async (work) => {
      // If complete, redis key is deleted, database contains all information
      if (work.status === 'complete') {
        return { import_processed_number: work.completed_number, import_expected_number: work.import_expected_number };
      }
      // If running, information in redis.
      const redisData = await redisGetWork(work.id);
      // If data in redis not exist, just send default values
      if (redisData === undefined) {
        return { import_processed_number: null, import_expected_number: null };
      }
      return redisData;
    },
  },
  Synchronizer: {
    user: (sync, _, { user }) => findUserById(user, sync.user_id),
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
      ping: () => pingWork(user, id),
      reportExpectation: ({ error }) => reportExpectation(user, id, error),
      addExpectations: ({ expectations }) => updateExpectationsNumber(user, id, expectations),
      toReceived: ({ message }) => updateReceivedTime(user, id, message),
      toProcessed: ({ message, inError }) => updateProcessedTime(user, id, message, inError),
    }),
    workDelete: (_, { connectorId }, { user }) => deleteWorkForConnector(user, connectorId),
    // Sync part
    synchronizerAdd: (_, { input }, { user }) => registerSync(user, input),
    synchronizerEdit: (_, { id }, { user }) => ({
      delete: () => syncDelete(user, id),
      fieldPatch: ({ input }) => syncEditField(user, id, input),
      contextPatch: ({ input }) => syncEditContext(user, id, input),
      contextClean: () => syncCleanContext(user, id),
    }),
    synchronizerStart: (_, { id }, { user }) => patchSync(user, id, { running: true }),
    synchronizerStop: (_, { id }, { user }) => patchSync(user, id, { running: false }),
    synchronizerTest: (_, { input }, { user }) => testSync(user, input),
  },
};

export default connectorResolvers;
