import {
  computeWorkStatus,
  connectorDelete,
  connectorForWork,
  connectorsForExport,
  connectorTriggerUpdate,
  fetchRemoteStreams,
  findAllSync,
  findSyncById,
  patchSync,
  pingConnector,
  queueDetails,
  registerConnector,
  registerSync,
  resetStateConnector,
  syncCleanContext,
  syncDelete,
  syncEditContext,
  syncEditField,
  testSync
} from '../domain/connector';
import {
  createWork,
  deleteWork,
  deleteWorkForConnector,
  findAll,
  findById,
  pingWork,
  reportExpectation,
  updateExpectationsNumber,
  updateProcessedTime,
  updateReceivedTime,
  worksForConnector
} from '../domain/work';
import { batchCreator } from '../domain/user';
import { now } from '../utils/format';
import { connector, connectors, connectorsForAnalysis, connectorsForImport, connectorsForNotification, connectorsForWorker } from '../database/repository';
import { batchLoader } from '../database/middleware';

const creatorLoader = batchLoader(batchCreator);

const connectorResolvers = {
  Query: {
    connector: (_, { id }, context) => connector(context, context.user, id),
    connectors: (_, __, context) => connectors(context, context.user),
    connectorsForWorker: (_, __, context) => connectorsForWorker(context, context.user),
    connectorsForExport: (_, __, context) => connectorsForExport(context, context.user),
    connectorsForImport: (_, __, context) => connectorsForImport(context, context.user),
    connectorsForAnalysis: (_, __, context) => connectorsForAnalysis(context, context.user),
    connectorsForNotification: (_, __, context) => connectorsForNotification(context, context.user),
    works: (_, args, context) => findAll(context, context.user, args),
    work: (_, { id }, context) => findById(context, context.user, id),
    synchronizer: (_, { id }, context) => findSyncById(context, context.user, id),
    synchronizers: (_, args, context) => findAllSync(context, context.user, args),
    synchronizerFetch: (_, { input }, context) => fetchRemoteStreams(context, context.user, input),
  },
  Connector: {
    works: (cn, args, context) => worksForConnector(context, context.user, cn.id, args),
    connector_queue_details: (cn) => queueDetails(cn.id),
  },
  Work: {
    connector: (work, _, context) => connectorForWork(context, context.user, work.id),
    user: (work, _, context) => creatorLoader.load(work.user_id, context, context.user),
    tracking: (work) => computeWorkStatus(work),
  },
  Synchronizer: {
    user: (sync, _, context) => creatorLoader.load(sync.user_id, context, context.user),
  },
  Mutation: {
    deleteConnector: (_, { id }, context) => connectorDelete(context, context.user, id),
    registerConnector: (_, { input }, context) => registerConnector(context, context.user, input),
    resetStateConnector: (_, { id }, context) => resetStateConnector(context, context.user, id),
    pingConnector: (_, { id, state }, context) => pingConnector(context, context.user, id, state),
    updateConnectorTrigger: (_, { id, input }, context) => connectorTriggerUpdate(context, context.user, id, input),
    // Work part
    workAdd: async (_, { connectorId, friendlyName }, context) => {
      const connectorEntity = await connector(context, context.user, connectorId);
      return createWork(context, context.user, connectorEntity, friendlyName, connectorEntity.id, { receivedTime: now() });
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
