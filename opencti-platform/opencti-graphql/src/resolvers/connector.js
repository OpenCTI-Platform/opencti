import {
  fetchRemoteStreams,
  findSyncById,
  findSyncPaginated,
  patchSync,
  registerSync,
  syncAddInputFromImport,
  syncCleanContext,
  syncDelete,
  syncEditContext,
  syncEditField,
  synchronizerAddAutoUser,
  synchronizerExport,
  testSync,
} from '../domain/connector';
import { computeWorkStatus, connectorForWork } from '../domain/connector';
import {
  addDraftContext,
  createWork,
  deleteWork,
  deleteWorkForConnector,
  findById,
  findWorkPaginated,
  isWorkAlive,
  pingWork,
  reportExpectation,
  updateExpectationsNumber,
  updateProcessedTime,
  updateReceivedTime,
  worksForConnector,
} from '../domain/work';
import { now } from '../utils/format';
import { connector } from '../modules/connector/connector-domain';
import { getConnectorQueueSize } from '../modules/connector/connector-rabbitmq';
import { loadCreator } from '../database/members';
import { readSyncConsumerMetrics } from '../graphql/syncConsumerMetrics';
import { findIngestionLogsForFeed } from '../modules/ingestion/ingestion-common';

const connectorResolvers = {
  Query: {
    works: (_, args, context) => findWorkPaginated(context, context.user, args),
    work: (_, { id }, context) => findById(context, context.user, id),
    isWorkAlive: (_, { id }, context) => isWorkAlive(context, context.user, id),
    synchronizer: (_, { id }, context) => findSyncById(context, context.user, id),
    synchronizerLogs: async (_, { id }, context) => {
      const sync = await findSyncById(context, context.user, id);
      return findIngestionLogsForFeed(sync.internal_id ?? sync.id);
    },
    synchronizerAddInputFromImport: (_, { file }) => syncAddInputFromImport(file),
    synchronizers: (_, args, context) => findSyncPaginated(context, context.user, args),
    synchronizerFetch: (_, { input }, context) => fetchRemoteStreams(context, context.user, input),
  },
  Work: {
    connector: (work, _, context) => connectorForWork(context, context.user, work.id),
    user: (work, _, context) => loadCreator(context, context.user, work.user_id),
    tracking: (work) => computeWorkStatus(work),
  },
  Connector: {
    works: (cn, args, context) => worksForConnector(context, context.user, cn.id, args),
  },
  Synchronizer: {
    user: (sync, _, context) => loadCreator(context, context.user, sync.user_id),
    queue_messages: async (sync, _, context) => getConnectorQueueSize(context, context.user, sync.id),
    toConfigurationExport: (synchronizer) => synchronizerExport(synchronizer),
    consumer_metrics: (sync) => readSyncConsumerMetrics(sync.id),
    ingestionLogs: (sync) => findIngestionLogsForFeed(sync.internal_id ?? sync.id),
  },
  Mutation: {
    workAdd: async (_, { connectorId, friendlyName, isMultiPartWork }, context) => {
      const connectorEntity = await connector(context, context.user, connectorId);
      return createWork(context, context.user, connectorEntity, friendlyName, connectorEntity.id, {
        receivedTime: now(),
        isMultiPartWork: isMultiPartWork ?? false,
      });
    },
    workEdit: (_, { id }, context) => ({
      delete: () => deleteWork(context, context.user, id),
      ping: () => pingWork(context, context.user, id),
      reportExpectation: ({ error }) => reportExpectation(context, context.user, id, error),
      addExpectations: ({ expectations }) => updateExpectationsNumber(context, context.user, id, expectations),
      addDraftContext: ({ draftContext }) => addDraftContext(context, context.user, id, draftContext),
      toReceived: ({ message }) => updateReceivedTime(context, context.user, id, message),
      toProcessed: ({ message, inError }) => updateProcessedTime(context, context.user, id, message, inError),
    }),
    workDelete: (_, { connectorId }, context) => deleteWorkForConnector(context, context.user, connectorId),
    synchronizerAdd: (_, { input }, context) => registerSync(context, context.user, input),
    synchronizerAddAutoUser: (_, { id, input }, context) => synchronizerAddAutoUser(context, context.user, id, input),
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
