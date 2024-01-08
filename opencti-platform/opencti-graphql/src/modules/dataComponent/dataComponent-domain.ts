import { batchListThroughGetTo, batchLoadThroughGetTo, createEntity } from '../../database/middleware';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityDataComponent, RELATION_DATA_SOURCE } from './dataComponent-types';
import type { DataComponentAddInput, QueryDataComponentsArgs } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { RELATION_DETECTS } from '../../schema/stixCoreRelationship';
import type { DomainFindById } from '../../domain/domainTypes';

export const findById: DomainFindById<BasicStoreEntityDataComponent> = (context: AuthContext, user: AuthUser, dataComponentId: string) => {
  return storeLoadById(context, user, dataComponentId, ENTITY_TYPE_DATA_COMPONENT);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryDataComponentsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDataComponent>(context, user, [ENTITY_TYPE_DATA_COMPONENT], opts);
};

export const dataComponentAdd = async (context: AuthContext, user: AuthUser, dataComponent: DataComponentAddInput) => {
  const created = await createEntity(context, user, dataComponent, ENTITY_TYPE_DATA_COMPONENT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchDataSource = async (context: AuthContext, user: AuthUser, dataComponentId: string) => {
  return batchLoadThroughGetTo(context, user, dataComponentId, RELATION_DATA_SOURCE, ENTITY_TYPE_DATA_SOURCE);
};

export const batchAttackPatterns = async (context: AuthContext, user: AuthUser, dataComponentIds: Array<string>) => {
  return batchListThroughGetTo(context, user, dataComponentIds, RELATION_DETECTS, ENTITY_TYPE_ATTACK_PATTERN);
};
