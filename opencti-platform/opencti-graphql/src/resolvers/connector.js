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
    connector: (_, { id }, context) => loadConnectorById(context, context.user, id),
    connectors: (_, __, context) => connectors(context, context.user),
    connectorsForWorker: (_, __, context) => connectorsForWorker(context, context.user),
    connectorsForExport: (_, __, context) => connectorsForExport(context, context.user),
    connectorsForImport: (_, __, context) => connectorsForImport(context, context.user),
    works: (_, args, context) => findAll(context, context.user, args),
    work: (_, { id }, context) => findById(context, context.user, id),
    synchronizer: (_, { id }, context) => findSyncById(context, context.user, id),
    synchronizers: (_, args, context) => findAllSync(context, context.user, args),
  },
  Connector: {
    works: (connector, args, context) => worksForConnector(context, context.user, connector.id, args),
  },
  Work: {
    connector: (work, _, context) => connectorForWork(context, context.user, work.id),
    user: (work, _, context) => findUserById(context, context.user, work.user_id),
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
    user: (sync, _, context) => findUserById(context, context.user, sync.user_id),
  },
  Mutation: {
    deleteConnector: (_, { id }, context) => connectorDelete(context, context.user, id),
    registerConnector: (_, { input }, context) => registerConnector(context, context.user, input),
    resetStateConnector: (_, { id }, context) => resetStateConnector(context, context.user, id),
    pingConnector: (_, { id, state }, context) => pingConnector(context, context.user, id, state),
    // Work part
    workAdd: async (_, { connectorId, friendlyName }, context) => {
      const connector = await loadConnectorById(context, context.user, connectorId);
      return createWork(context, context.user, connector, friendlyName, connector.id, { receivedTime: now() });
    },
    workEdit: (_, { id }, context) => ({
      delete: () => deleteWork(context, context.user, id),
      ping: () => pingWork(context, context.user, id),
      reportExpectation: ({ error }) => reportExpectation(context, context.user, id, error),
      addExpectations: ({ expectations }) => updateExpectationsNumber(context, context.user, id, expectations),
      toReceived: ({ message }) => updateReceivedTime(context, context.user, id, message),
      toProcessed: ({ message, inError }) => updateProcessedTime(context, context.user, id, message, inError),
    }),
    workDelete: (_, { connectorId }, context) => deleteWorkForConnector(context, context.user, connectorId),
    // Sync part
    synchronizerAdd: (_, { input }, context) => registerSync(context, context.user, input),
    synchronizerEdit: (_, { id }, context) => ({
      delete: () => syncDelete(context, context.user, id),
      fieldPatch: ({ input }) => syncEditField(context, context.user, id, input),
      contextPatch: ({ input }) => syncEditContext(context, context.user, id, input),
      contextClean: () => syncCleanContext(context, context.user, id),
    }),
    synchronizerStart: (_, { id }, context) => patchSync(context, context.user, id, { running: true }),
    synchronizerStop: (_, { id }, context) => patchSync(context, context.user, id, { running: false }),
    synchronizerTest: (_, { input }, context) => testSync(context, context.user, input),
  },
};

export default connectorResolvers;
