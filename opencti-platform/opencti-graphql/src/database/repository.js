import { filter, includes, map, pipe } from 'ramda';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { connectorConfig, INTERNAL_SYNC_QUEUE } from './rabbitmq';
import { sinceNowInMinutes } from '../utils/format';
import { CONNECTOR_INTERNAL_ENRICHMENT, CONNECTOR_INTERNAL_IMPORT_FILE } from '../schema/general';
import { listEntities } from './middleware-loader';

// region global queries
// TODO Will be removed during typescript migration
export const buildFilters = (args = {}) => {
  const builtFilters = { ...args };
  const { types = [], entityTypes = [], relationshipTypes = [] } = args;
  const { elementId, elementWithTargetTypes = [] } = args;
  const { fromId, fromRole, fromTypes = [] } = args;
  const { toId, toRole, toTypes = [] } = args;
  const { filters = [] } = args;
  // Config
  const customFilters = [...(filters ?? [])];
  // region element
  const nestedElement = [];
  if (elementId) {
    nestedElement.push({ key: 'internal_id', values: [elementId] });
  }
  if (nestedElement.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedElement });
  }
  const nestedElementTypes = [];
  if (elementWithTargetTypes && elementWithTargetTypes.length > 0) {
    nestedElementTypes.push({ key: 'types', values: elementWithTargetTypes });
  }
  if (nestedElementTypes.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedElementTypes });
  }
  // endregion
  // region from filtering
  const nestedFrom = [];
  if (fromId) {
    nestedFrom.push({ key: 'internal_id', values: [fromId] });
  }
  if (fromTypes && fromTypes.length > 0) {
    nestedFrom.push({ key: 'types', values: fromTypes });
  }
  if (fromRole) {
    nestedFrom.push({ key: 'role', values: [fromRole] });
  } else if (fromId || (fromTypes && fromTypes.length > 0)) {
    nestedFrom.push({ key: 'role', values: ['*_from'], operator: 'wildcard' });
  }
  if (nestedFrom.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedFrom });
  }
  // endregion
  // region to filtering
  const nestedTo = [];
  if (toId) {
    nestedTo.push({ key: 'internal_id', values: [toId] });
  }
  if (toTypes && toTypes.length > 0) {
    nestedTo.push({ key: 'types', values: toTypes });
  }
  if (toRole) {
    nestedTo.push({ key: 'role', values: [toRole] });
  } else if (toId || (toTypes && toTypes.length > 0)) {
    nestedTo.push({ key: 'role', values: ['*_to'], operator: 'wildcard' });
  }
  if (nestedTo.length > 0) {
    customFilters.push({ key: 'connections', nested: nestedTo });
  }
  // endregion
  // Override some special filters
  builtFilters.types = [...(types ?? []), ...entityTypes, ...relationshipTypes];
  builtFilters.filters = customFilters;
  return builtFilters;
};
// endregion

// region connectors
export const completeConnector = (connector) => {
  if (connector) {
    const completed = { ...connector };
    completed.connector_scope = connector.connector_scope ? connector.connector_scope.split(',') : [];
    completed.config = connectorConfig(connector.id);
    completed.active = sinceNowInMinutes(connector.updated_at) < 5;
    return completed;
  }
  return null;
};

export const connectors = (user) => {
  return listEntities(user, [ENTITY_TYPE_CONNECTOR], { connectionFormat: false })
    .then((elements) => map((conn) => completeConnector(conn), elements));
};

export const connectorsForWorker = async (user) => {
  const registeredConnectors = await connectors(user);
  registeredConnectors.push({
    id: 'sync',
    name: 'Internal sync connector',
    connector_scope: [],
    config: connectorConfig(INTERNAL_SYNC_QUEUE),
    active: true
  });
  return registeredConnectors;
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

export const connectorsFor = async (user, type, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  const connects = await connectors(user);
  return filterConnectors(connects, type, scope, onlyAlive, onlyAuto, onlyContextual);
};

export const connectorsForEnrichment = async (user, scope, onlyAlive = false, onlyAuto = false) => {
  return connectorsFor(user, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);
};

export const connectorsEnrichment = (instances, scope, onlyAlive = false, onlyAuto = false) => {
  return filterConnectors(instances, CONNECTOR_INTERNAL_ENRICHMENT, scope, onlyAlive, onlyAuto);
};

export const connectorsForImport = async (user, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  return connectorsFor(user, CONNECTOR_INTERNAL_IMPORT_FILE, scope, onlyAlive, onlyAuto, onlyContextual);
};
// endregion
