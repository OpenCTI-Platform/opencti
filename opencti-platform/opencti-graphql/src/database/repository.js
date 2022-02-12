import { assoc, filter, includes, map, pipe } from 'ramda';
import { READ_ENTITIES_INDICES } from './utils';
import { elPaginate } from './engine';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { connectorConfig } from './rabbitmq';
import { sinceNowInMinutes } from '../utils/format';

// region global queries
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

export const listEntities = async (user, entityTypes, args = {}) => {
  const { indices = READ_ENTITIES_INDICES } = args;
  const paginateArgs = buildFilters({ entityTypes, ...args });
  return elPaginate(user, indices, paginateArgs);
};
// endregion

// region connectors
export const completeConnector = (connector) => {
  if (connector) {
    return pipe(
      assoc('connector_scope', connector.connector_scope ? connector.connector_scope.split(',') : []),
      assoc('config', connectorConfig(connector.id)),
      assoc('active', sinceNowInMinutes(connector.updated_at) < 5)
    )(connector);
  }
  return null;
};

export const connectors = (user) => {
  return listEntities(user, [ENTITY_TYPE_CONNECTOR], { connectionFormat: false }).then((elements) =>
    map((conn) => completeConnector(conn), elements)
  );
};

export const connectorsFor = async (user, type, scope, onlyAlive = false, onlyAuto = false, onlyContextual = false) => {
  const connects = await connectors(user);
  return pipe(
    filter((c) => c.connector_type === type),
    filter((c) => (onlyAlive ? c.active === true : true)),
    filter((c) => (onlyAuto ? c.auto === true : true)),
    filter((c) => (onlyContextual ? c.only_contextual === true : true)),
    // eslint-disable-next-line prettier/prettier
    filter((c) =>
      scope && c.connector_scope && c.connector_scope.length > 0
        ? includes(
            scope.toLowerCase(),
            map((s) => s.toLowerCase(), c.connector_scope)
          )
        : true
    )
  )(connects);
};
// endregion
