import { filter, includes, map, pipe } from 'ramda';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { connectorConfig } from './rabbitmq';
import { sinceNowInMinutes } from '../utils/format';
import { CONNECTOR_INTERNAL_ANALYSIS, CONNECTOR_INTERNAL_ENRICHMENT, CONNECTOR_INTERNAL_IMPORT_FILE, CONNECTOR_INTERNAL_NOTIFICATION } from '../schema/general';
import { listEntities, storeLoadById } from './middleware-loader';
import { INTERNAL_PLAYBOOK_QUEUE, INTERNAL_SYNC_QUEUE, isEmptyField } from './utils';
import { BUILTIN_NOTIFIERS_CONNECTORS } from '../modules/notifier/notifier-statics';
import { builtInConnector, builtInConnectorsRuntime } from '../connector/connector-domain';

export const completeConnector = (connector) => {
  if (connector) {
    const completed = { ...connector };
    completed.connector_scope = connector.connector_scope ? connector.connector_scope.split(',') : [];
    completed.config = connectorConfig(connector.id);
    completed.active = connector.built_in ? true : (sinceNowInMinutes(connector.updated_at) < 5);
    return completed;
  }
  return null;
};

export const connector = async (context, user, id) => {
  // Database connector
  const element = await storeLoadById(context, user, id, ENTITY_TYPE_CONNECTOR)
    .then((conn) => completeConnector(conn));
  if (isEmptyField(element)) {
    // Built in connector
    const conn = builtInConnector(id);
    return completeConnector(conn);
  }
  return element;
};

export const connectors = async (context, user) => {
  const elements = await listEntities(context, user, [ENTITY_TYPE_CONNECTOR], { connectionFormat: false });
  const builtInElements = await builtInConnectorsRuntime(context, user);
  return map((conn) => completeConnector(conn), [...elements, ...builtInElements]);
};

export const connectorsForWorker = async (context, user) => {
  const registeredConnectors = await connectors(context, user);
  // Register internal queues
  registeredConnectors.push({
    id: INTERNAL_SYNC_QUEUE,
    name: 'Internal sync manager',
    connector_scope: [],
    config: connectorConfig(INTERNAL_SYNC_QUEUE),
    active: true
  });
  registeredConnectors.push({
    id: INTERNAL_PLAYBOOK_QUEUE,
    name: 'Internal playbook manager',
    connector_scope: [],
    config: connectorConfig(INTERNAL_PLAYBOOK_QUEUE),
    active: true
  });
  return registeredConnectors;
};

export const connectorsForPlaybook = async (context, user) => {
  const registeredConnectors = await connectors(context, user);
  return registeredConnectors.filter((r) => r.playbook_compatible === true);
};

const filterConnectors = (instances, type, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  return pipe(
    filter((c) => c.connector_type === type),
    filter((c) => (onlyAlive ? c.active === true : true)),
    filter((c) => (onlyAuto ? c.auto === true : true)),
    filter((c) => (onlyContextual ? c.only_contextual === true : true)),
    filter((c) => (scope && c.connector_scope && c.connector_scope.length > 0
      ? includes(scope.toLowerCase(), map((s) => s.toLowerCase(), c.connector_scope))
      : true))
  )(instances);
};

export const connectorsFor = async (context, user, type, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  const connects = await connectors(context, user);
  return filterConnectors(connects, type, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForEnrichment = async (context, user, scope, onlyAlive = false, onlyAuto = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);
};

export const connectorsEnrichment = (instances, scope, onlyAlive = false, onlyAuto = false) => {
  return filterConnectors(instances, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);
};

export const connectorsForImport = async (context, user, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForAnalysis = async (context, user, scope = null, onlyAlive = true, onlyAuto = false, onlyContextual = false) => {
  return connectorsFor(context, user, CONNECTOR_INTERNAL_ANALYSIS, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForNotification = async (context, user, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  const notificationConnectors = await connectorsFor(context, user, CONNECTOR_INTERNAL_NOTIFICATION, scope, onlyAlive, onlyAuto, onlyContextual);
  return [...notificationConnectors, ...Object.values(BUILTIN_NOTIFIERS_CONNECTORS)];
};
