import { batchListThroughGetFrom, createEntity, storeLoadById } from '../../database/middleware';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityDataSource } from './dataSource-types';
import type { DataSourceAddInput, QueryDataSourcesArgs } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { RELATION_DATA_SOURCE } from '../dataComponent/dataComponent-domain';
import { stixDomainObjectEditField } from '../../domain/stixDomainObject';

export const findById = (context: AuthContext, user: AuthUser, dataSourceId: string): BasicStoreEntityDataSource => {
  return storeLoadById(context, user, dataSourceId, ENTITY_TYPE_DATA_SOURCE) as unknown as BasicStoreEntityDataSource;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryDataSourcesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDataSource>(context, user, [ENTITY_TYPE_DATA_SOURCE], opts);
};

export const dataSourceAdd = async (context: AuthContext, user: AuthUser, dataSource: DataSourceAddInput) => {
  const created = await createEntity(context, user, dataSource, ENTITY_TYPE_DATA_SOURCE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchDataComponents = async (context: AuthContext, user: AuthUser, dataSourceIds: [string]) => {
  return batchListThroughGetFrom(context, user, dataSourceIds, RELATION_DATA_SOURCE, ENTITY_TYPE_DATA_COMPONENT);
};

export const dataSourceDataComponentAdd = async (context: AuthContext, user: AuthUser, dataSourceId: string, dataComponentId: string) => {
  await stixDomainObjectEditField(context, user, dataComponentId, { key: 'dataSource', value: [dataSourceId] });
  return findById(context, user, dataSourceId);
};

export const dataSourceDataComponentDelete = async (context: AuthContext, user: AuthUser, dataSourceId: string, dataComponentId: string) => {
  await stixDomainObjectEditField(context, user, dataComponentId, { key: 'dataSource', value: [null] });
  return findById(context, user, dataSourceId);
};
