import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_CONNECTOR_MANAGER } from '../../schema/internalObject';
import { fullEntitiesList, topEntitiesList, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityConnector, BasicStoreEntityConnectorManager } from './connector-types';
import { FilterMode, FilterOperator } from '../../generated/graphql';

export const findConnectorById = (context: AuthContext, user: AuthUser, connectorId: string) => {
  return storeLoadById<BasicStoreEntityConnector>(context, user, connectorId, ENTITY_TYPE_CONNECTOR);
};

export const findConnectors = (context: AuthContext, user: AuthUser) => {
  return topEntitiesList<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR]);
};

export const findConnectorManagerById = (context: AuthContext, user: AuthUser, managerId: string) => {
  return storeLoadById<BasicStoreEntityConnectorManager>(context, user, managerId, ENTITY_TYPE_CONNECTOR_MANAGER);
};

export const findConnectorManagers = (context: AuthContext, user: AuthUser) => {
  return fullEntitiesList<BasicStoreEntityConnectorManager>(context, user, [ENTITY_TYPE_CONNECTOR_MANAGER]);
};

export const findManagedConnectors = (context: AuthContext, user: AuthUser) => {
  return topEntitiesList<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['catalog_id'], values: ['EXISTS'] }],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
};

export const findManagedConnectorsByCatalogId = async (
  context: AuthContext,
  user: AuthUser,
  catalogId: string,
) => {
  return fullEntitiesList<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR], {
    filters: {
      filters: [{
        key: ['catalog_id'],
        values: [catalogId],
        operator: FilterOperator.Eq,
      }],
      filterGroups: [],
      mode: FilterMode.And,
    },
  });
};
