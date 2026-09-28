import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import type { BasicStoreEntityConnector } from '../../types/connector';
import type { AuthContext, AuthUser } from '../../types/user';

export const findManagedConnectorsByCatalogId = async (
  context: AuthContext,
  user: AuthUser,
  catalogId: string,
) => {
  return await fullEntitiesList<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR], {
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
