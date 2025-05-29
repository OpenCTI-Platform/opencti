import {
  computeWorkStatus,
  connectorDelete,
  connectorForWork,
  connectorsForExport,
  connectorTriggerUpdate,
  connectorUpdateLogs,
  connectorUser,
  fetchRemoteStreams,
  findAllSync,
  findSyncById,
  managedConnectorAdd,
  managedConnectorEdit,
  patchSync,
  pingConnector,
  queueDetails,
  registerConnector,
  registerConnectorsManager,
  registerSync,
  resetStateConnector,
  syncCleanContext,
  syncDelete,
  syncEditContext,
  syncEditField,
  testSync,
  updateConnectorCurrentStatus,
  updateConnectorManagerStatus,
  updateConnectorRequestedStatus
} from '../domain/connector';
import {
  addDraftContext,
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
import { now, sinceNowInMinutes } from '../utils/format';
import {
  computeManagerConnectorContract,
  computeManagerConnectorConfiguration,
  computeManagerConnectorImage,
  computeManagerContractHash,
  connector,
  connectorManager,
  connectorManagers,
  connectors,
  connectorsForAnalysis,
  connectorsForImport,
  connectorsForManagers,
  connectorsForNotification,
  connectorsForWorker
} from '../database/repository';
import { batchLoader } from '../database/middleware';
import { getConnectorQueueSize } from '../database/rabbitmq';
import { redisGetConnectorLogs } from '../database/redis';
import pjson from '../../package.json';
import { COMPOSER_FF } from '../modules/catalog/catalog-types';
import { enforceEnableFeatureFlag } from '../utils/access';

const creatorLoader = batchLoader(batchCreator);
export const PLATFORM_VERSION = pjson.version;

const connectorResolvers = {
  Query: {
    connector: (_, { id }, context) => connector(context, context.user, id),
    connectors: (_, __, context) => connectors(context, context.user),
    connectorsForManagers: (_, __, context) => connectorsForManagers(context, context.user),
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
    // region new managed connectors
    connectorManager: (_, { managerId }, context) => connectorManager(context, context.user, managerId),
    connectorManagers: (_, __, context) => connectorManagers(context, context.user),
    // endregion
  },
  Connector: {
    works: (cn, args, context) => worksForConnector(context, context.user, cn.id, args),
    connector_queue_details: (cn) => queueDetails(cn.id),
    connector_user: (cn, _, context) => connectorUser(context, context.user, cn.connector_user_id),
    manager_connector_logs: (cn) => redisGetConnectorLogs(cn.id),
    manager_contract_hash: (cn, _, context) => computeManagerContractHash(context, context.user, cn),
    manager_contract_definition: (cn, _, context) => computeManagerConnectorContract(context, context.user, cn),
    manager_contract_configuration: (cn, _, context) => computeManagerConnectorConfiguration(context, context.user, cn),
    manager_contract_image: (cn) => computeManagerConnectorImage(cn),
  },
  ManagedConnector: {
    manager_connector_logs: (cn) => redisGetConnectorLogs(cn.id),
    manager_contract_hash: (cn, _, context) => computeManagerContractHash(context, context.user, cn),
    manager_contract_configuration: (cn, _, context) => computeManagerConnectorConfiguration(context, context.user, cn),
    manager_contract_image: (cn) => computeManagerConnectorImage(cn),
    connector_user: (cn, _, context) => connectorUser(context, context.user, cn.connector_user_id),
  },
  ConnectorManager: {
    active: (cm) => sinceNowInMinutes(cm.updated_at) < 5,
    about_version: () => PLATFORM_VERSION
  },
  Work: {
    connector: (work, _, context) => connectorForWork(context, context.user, work.id),
    user: (work, _, context) => creatorLoader.load(work.user_id, context, context.user),
    tracking: (work) => computeWorkStatus(work),
  },
  Synchronizer: {
    user: (sync, _, context) => creatorLoader.load(sync.user_id, context, context.user),
    queue_messages: async (sync, _, context) => getConnectorQueueSize(context, context.user, sync.id)
  },
  Mutation: {
    deleteConnector: (_, { id }, context) => connectorDelete(context, context.user, id),
    registerConnector: (_, { input }, context) => registerConnector(context, context.user, input),
    resetStateConnector: (_, { id }, context) => resetStateConnector(context, context.user, id),
    pingConnector: (_, { id, state, connectorInfo }, context) => pingConnector(context, context.user, id, state, connectorInfo),
    updateConnectorTrigger: (_, { id, input }, context) => connectorTriggerUpdate(context, context.user, id, input),
    // region new managed connectors
    managedConnectorAdd: (_, { input }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return managedConnectorAdd(context, context.user, input);
    },
    managedConnectorEdit: (_, { input }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return managedConnectorEdit(context, context.user, input);
    },
    updateConnectorManagerStatus: (_, { input }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return updateConnectorManagerStatus(context, context.user, input);
    },
    registerConnectorsManager: (_, { input }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return registerConnectorsManager(context, context.user, input);
    },
    updateConnectorRequestedStatus: (_, { input }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return updateConnectorRequestedStatus(context, context.user, input);
    },
    updateConnectorCurrentStatus: (_, { input }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return updateConnectorCurrentStatus(context, context.user, input);
    },
    updateConnectorLogs: (_, { input }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return connectorUpdateLogs(context, context.user, input);
    },
    // endregion
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
      addDraftContext: ({ draftContext }) => addDraftContext(context, context.user, id, draftContext),
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
