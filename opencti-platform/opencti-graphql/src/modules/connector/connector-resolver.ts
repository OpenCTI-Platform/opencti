import { ConnectorPriorityGroup, type EditInput, type Resolvers } from '../../generated/graphql';
import { ingestionHealthFieldResolvers } from '../ingestionHealth/ingestionHealth-resolvers';
import {
  computeConnectorContractConfiguration,
  computeConnectorContractHash,
  computeConnectorContractImage,
  computeConnectorCurrentStatus,
  computeConnectorHealthMetrics,
  computeConnectorLogs,
  computeConnectorRequestedStatus,
  computeConnectorUptime,
  computeManagedConnectorContractConfiguration,
  computeManagedConnectorContractHash,
  computeManagedConnectorContractImage,
  computeManagedConnectorCurrentStatus,
  computeManagedConnectorHealthMetrics,
  computeManagedConnectorLogs,
  computeManagedConnectorRequestedStatus,
  computeManagedConnectorUptime,
  computeManagerConnectorContract,
  computeManagerConnectorExcerpt,
  connector,
  connectorManager,
  connectorManagers,
  connectors,
  connectorsForAnalysis,
  connectorsForImport,
  connectorsForManagers,
  connectorsForNotification,
  connectorsForWorker,
  getConnectorJwks,
  connectorDelete,
  connectorTriggerUpdate,
  connectorUpdateHealth,
  connectorUpdateLogs,
  connectorUser,
  connectorsForExport,
  pingConnector,
  queueDetails,
  registerConnector,
  registerConnectorsManager,
  resetStateConnector,
  loadConnectorErrors,
  resolveConnectorInfo,
  managedConnectorAdd,
  managedConnectorEdit,
  updateConnectorCurrentStatus,
  updateConnectorManagerStatus,
  updateConnectorRequestedStatus,
} from './connector-domain';
import { PLATFORM_VERSION } from '../../config/conf';
import { assessConnectorMigration, migrateConnectorToManaged } from './connector-migration';
import { sinceNowInMinutes } from '../../utils/format';
import { waitForManagedConnectorAutoUpgrade } from './managed-connector-auto-upgrade-readiness';

const connectorResolvers: Resolvers = {
  Query: {
    connector: (_, { id }, context) => connector(context, context.user, id),
    connectors: (_, __, context) => connectors(context, context.user),
    connectorsForManagers: async (_, __, context) => {
      await waitForManagedConnectorAutoUpgrade();
      return connectorsForManagers(context, context.user);
    },
    connectorsForWorker: (_, __, context) => connectorsForWorker(context, context.user),
    connectorsForExport: (_, __, context) => connectorsForExport(context, context.user),
    connectorsForImport: (_, __, context) => connectorsForImport(context, context.user),
    connectorsForAnalysis: (_, __, context) => connectorsForAnalysis(context, context.user),
    connectorsForNotification: (_, __, context) => connectorsForNotification(context, context.user),
    connectorManager: (_, { managerId }, context) => connectorManager(context, context.user, managerId),
    connectorManagers: (_, __, context) => connectorManagers(context, context.user),
    connectorMigrationAssessment: (_, { connectorId, containerImage, configuration }, context) => {
      return assessConnectorMigration(context, context.user, connectorId, containerImage, configuration);
    },
  },
  Connector: {
    connector_info: (cn) => resolveConnectorInfo(cn),
    connector_queue_details: (cn) => queueDetails(cn.id),
    connector_priority_group: (cn) => cn.connector_priority_group ?? ConnectorPriorityGroup.Default,
    connector_user: (cn, _, context) => connectorUser(context, context.user, cn.connector_user_id),
    manager_current_status: (cn) => computeConnectorCurrentStatus(cn),
    manager_requested_status: (cn) => computeConnectorRequestedStatus(cn),
    manager_connector_logs: (cn) => computeConnectorLogs(cn),
    manager_health_metrics: (cn, _, context) => computeConnectorHealthMetrics(context, context.user, cn),
    manager_connector_uptime: (cn, _, context) => computeConnectorUptime(context, context.user, cn),
    manager_contract_hash: (cn, _, context) => computeConnectorContractHash(context, context.user, cn),
    manager_contract_definition: (cn, _, context) => computeManagerConnectorContract(context, context.user, cn),
    manager_contract_configuration: (cn, _, context) => computeConnectorContractConfiguration(context, context.user, cn),
    manager_contract_image: (cn) => computeConnectorContractImage(cn),
    manager_contract_excerpt: (cn, _, context) => computeManagerConnectorExcerpt(context, context.user, cn),
    update_available: async (cn, _, context) => (await context.batch.connectorUpdateStatusBatchLoader.load(cn)).update_available,
    latest_compatible_version: async (cn, _, context) => (await context.batch.connectorUpdateStatusBatchLoader.load(cn)).latest_compatible_version,
    has_newer_incompatible_version: async (cn, _, context) => (await context.batch.connectorUpdateStatusBatchLoader.load(cn)).has_newer_incompatible_version,
    jwks: () => getConnectorJwks(),
    ...ingestionHealthFieldResolvers,
  },
  ConnectorInfo: {
    errors: (connectorInfo) => loadConnectorErrors(connectorInfo.connector_id),
  },
  ManagedConnector: {
    manager_current_status: (cn) => computeManagedConnectorCurrentStatus(cn),
    manager_requested_status: (cn) => computeManagedConnectorRequestedStatus(cn),
    manager_connector_logs: (cn) => computeManagedConnectorLogs(cn),
    manager_health_metrics: (cn, _, context) => computeManagedConnectorHealthMetrics(context, context.user, cn),
    manager_connector_uptime: (cn, _, context) => computeManagedConnectorUptime(context, context.user, cn),
    manager_contract_hash: (cn, _, context) => computeManagedConnectorContractHash(context, context.user, cn),
    manager_contract_configuration: (cn, _, context) => computeManagedConnectorContractConfiguration(context, context.user, cn),
    manager_contract_image: (cn) => computeManagedConnectorContractImage(cn),
    connector_user: (cn, _, context) => connectorUser(context, context.user, cn.connector_user_id),
  },
  ConnectorManager: {
    active: (cm) => sinceNowInMinutes(cm.last_sync_execution) < 5,
    about_version: () => PLATFORM_VERSION,
  },
  Mutation: {
    deleteConnector: (_, { id }, context) => connectorDelete(context, context.user, id),
    registerConnector: (_, { input }, context) => registerConnector(context, context.user, input!),
    resetStateConnector: (_, { id }, context) => resetStateConnector(context, context.user, id),
    pingConnector: (_, { id, state, connectorInfo }, context) => pingConnector(context, context.user, id, state, connectorInfo),
    updateConnectorTrigger: (_, { id, input }, context) => connectorTriggerUpdate(context, context.user, id, input as EditInput[]),
    managedConnectorAdd: (_, { input }, context) => managedConnectorAdd(context, context.user, input!),
    managedConnectorEdit: (_, { input }, context) => managedConnectorEdit(context, context.user, input!),
    updateConnectorManagerStatus: (_, { input }, context) => updateConnectorManagerStatus(context, context.user, input!),
    registerConnectorsManager: (_, { input }, context) => registerConnectorsManager(context, context.user, input!),
    updateConnectorRequestedStatus: (_, { input }, context) => updateConnectorRequestedStatus(context, context.user, input),
    updateConnectorCurrentStatus: (_, { input }, context) => updateConnectorCurrentStatus(context, context.user, input),
    updateConnectorLogs: (_, { input }, context) => connectorUpdateLogs(context, context.user, input),
    updateConnectorHealth: (_, { input }, context) => connectorUpdateHealth(context, context.user, input),
    connectorMigrateToManaged: (_, { input }, context) => {
      const { connectorId, containerImage, configuration, resetConnectorState, convertUserToServiceAccount } = input;
      return migrateConnectorToManaged(
        context,
        context.user,
        connectorId,
        containerImage,
        configuration,
        convertUserToServiceAccount,
        resetConnectorState,
      );
    },
  },
};

export default connectorResolvers;
