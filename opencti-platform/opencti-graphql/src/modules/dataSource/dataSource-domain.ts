import { createEntity } from '../../database/middleware';
import { pageEntitiesConnection, pageRegardingEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityDataSource } from './dataSource-types';
import type { DataSourceAddInput, QueryDataSourcesArgs } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { INPUT_DATA_SOURCE, RELATION_DATA_SOURCE } from '../dataComponent/dataComponent-types';
import type { DomainFindById } from '../../domain/domainTypes';
import type { BasicStoreEntity } from '../../types/store';

export const findById: DomainFindById<BasicStoreEntityDataSource> = (context: AuthContext, user: AuthUser, dataSourceId: string) => {
  return storeLoadById(context, user, dataSourceId, ENTITY_TYPE_DATA_SOURCE);
};

export const findDatasourcePaginated = (context: AuthContext, user: AuthUser, opts: QueryDataSourcesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityDataSource>(context, user, [ENTITY_TYPE_DATA_SOURCE], opts);
};

export const dataSourceAdd = async (context: AuthContext, user: AuthUser, dataSource: DataSourceAddInput) => {
  const created = await createEntity(context, user, dataSource, ENTITY_TYPE_DATA_SOURCE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const dataComponentsPaginated = async <T extends BasicStoreEntity> (context: AuthContext, user: AuthUser, dataSourceId: string, opts: QueryDataSourcesArgs) => {
  return pageRegardingEntitiesConnection<T>(context, user, dataSourceId, RELATION_DATA_SOURCE, ENTITY_TYPE_DATA_COMPONENT, true, opts);
};

export const dataSourceDataComponentAdd = async (context: AuthContext, user: AuthUser, dataSourceId: string, dataComponentId: string) => {
  await stixDomainObjectEditField(context, user, dataComponentId, [{ key: INPUT_DATA_SOURCE, value: [dataSourceId] }]);
  return findById(context, user, dataSourceId);
};

export const dataSourceDataComponentDelete = async (context: AuthContext, user: AuthUser, dataSourceId: string, dataComponentId: string) => {
  await stixDomainObjectEditField(context, user, dataComponentId, [{ key: INPUT_DATA_SOURCE, value: [null] }]);
  return findById(context, user, dataSourceId);
};
