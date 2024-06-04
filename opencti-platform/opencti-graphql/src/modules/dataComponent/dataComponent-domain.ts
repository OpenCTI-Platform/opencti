import { createEntity } from '../../database/middleware';
import {
  type EntityOptions,
  listEntitiesPaginated,
  listEntitiesThroughRelationsPaginated,
  loadEntityThroughRelationsPaginated,
  storeLoadById
} from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityDataComponent, RELATION_DATA_SOURCE } from './dataComponent-types';
import type { DataComponentAddInput, QueryDataComponentsArgs } from '../../generated/graphql';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { RELATION_DETECTS } from '../../schema/stixCoreRelationship';
import type { DomainFindById } from '../../domain/domainTypes';
import type { BasicStoreCommon } from '../../types/store';

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

export const withDataSource = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, dataComponentId: string) => {
  return loadEntityThroughRelationsPaginated<T>(context, user, dataComponentId, RELATION_DATA_SOURCE, ENTITY_TYPE_DATA_SOURCE, false);
};

export const attackPatternsPaginated = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, dataComponentId: string, args: EntityOptions<T>) => {
  return listEntitiesThroughRelationsPaginated<T>(context, user, dataComponentId, RELATION_DETECTS, ENTITY_TYPE_ATTACK_PATTERN, false, false, args);
};
