/* eslint-disable @typescript-eslint/ban-ts-comment */
// @ts-nocheck
import { ConnectorPriorityGroup } from '../../generated/graphql';
import {
  computeManagerConnectorConfiguration,
  computeManagerConnectorContract,
  computeManagerConnectorExcerpt,
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
  connectorsForWorker,
  getConnectorJwks,
  connectorDelete,
  connectorGetHealth,
  connectorGetUptime,
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
  managedConnectorAdd,
  managedConnectorEdit,
  updateConnectorCurrentStatus,
  updateConnectorManagerStatus,
  updateConnectorRequestedStatus,
} from './connector-domain';
import { redisGetConnectorLogs } from './connector-redis';
import pjson from '../../../package.json';
import { assessConnectorMigration, migrateConnectorToManaged } from './connector-migration';
import { sinceNowInMinutes } from '../../utils/format';

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
    connectorManager: (_, { managerId }, context) => connectorManager(context, context.user, managerId),
    connectorManagers: (_, __, context) => connectorManagers(context, context.user),
    connectorMigrationAssessment: (_, { connectorId, containerImage, configuration }, context) => {
      return assessConnectorMigration(context, context.user, connectorId, containerImage, configuration);
    },
  },
  Connector: {
    connector_queue_details: (cn) => queueDetails(cn.id),
    connector_priority_group: (cn) => cn.connector_priority_group ?? ConnectorPriorityGroup.Default,
    connector_user: (cn, _, context) => connectorUser(context, context.user, cn.connector_user_id),
    manager_connector_logs: (cn) => redisGetConnectorLogs(cn.id),
    manager_health_metrics: (cn, _, context) => connectorGetHealth(context, context.user, cn.id),
    manager_connector_uptime: (cn, _, context) => connectorGetUptime(context, context.user, cn.id),
    manager_contract_hash: (cn, _, context) => computeManagerContractHash(context, context.user, cn),
    manager_contract_definition: (cn, _, context) => computeManagerConnectorContract(context, context.user, cn),
    manager_contract_configuration: (cn, _, context) => computeManagerConnectorConfiguration(context, context.user, cn),
    manager_contract_image: (cn) => computeManagerConnectorImage(cn),
    manager_contract_excerpt: (cn, _, context) => computeManagerConnectorExcerpt(context, context.user, cn),
    jwks: () => getConnectorJwks(),
  },
  ManagedConnector: {
    manager_connector_logs: (cn) => redisGetConnectorLogs(cn.id),
    manager_health_metrics: (cn, _, context) => connectorGetHealth(context, context.user, cn.id),
    manager_connector_uptime: (cn, _, context) => connectorGetUptime(context, context.user, cn.id),
    manager_contract_hash: (cn, _, context) => computeManagerContractHash(context, context.user, cn),
    manager_contract_configuration: (cn, _, context) => {
      return computeManagerConnectorConfiguration(context, context.user, cn, { withEncrypted: true });
    },
    manager_contract_image: (cn) => computeManagerConnectorImage(cn),
    connector_user: (cn, _, context) => connectorUser(context, context.user, cn.connector_user_id),
  },
  ConnectorManager: {
    active: (cm) => sinceNowInMinutes(cm.last_sync_execution) < 5,
    about_version: () => PLATFORM_VERSION,
  },
  Mutation: {
    deleteConnector: (_, { id }, context) => connectorDelete(context, context.user, id),
    registerConnector: (_, { input }, context) => registerConnector(context, context.user, input),
    resetStateConnector: (_, { id }, context) => resetStateConnector(context, context.user, id),
    pingConnector: (_, { id, state, connectorInfo }, context) => pingConnector(context, context.user, id, state, connectorInfo),
    updateConnectorTrigger: (_, { id, input }, context) => connectorTriggerUpdate(context, context.user, id, input),
    managedConnectorAdd: (_, { input }, context) => managedConnectorAdd(context, context.user, input),
    managedConnectorEdit: (_, { input }, context) => managedConnectorEdit(context, context.user, input),
    updateConnectorManagerStatus: (_, { input }, context) => updateConnectorManagerStatus(context, context.user, input),
    registerConnectorsManager: (_, { input }, context) => registerConnectorsManager(context, context.user, input),
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
