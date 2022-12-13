import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, storeLoadById } from '../../database/middleware';
import {
  BasicStoreEntityCase,
  ENTITY_TYPE_CONTAINER_CASE,
} from './case-types';
import type { EntityOptions } from '../../database/middleware-loader';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { notify } from '../../database/redis';
import type { CaseAddInput } from '../../generated/graphql';

export const findById = (context: AuthContext, user: AuthUser, caseId: string): BasicStoreEntityCase => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE) as unknown as BasicStoreEntityCase;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCase>) => {
  return listEntitiesPaginated<BasicStoreEntityCase>(context, user, [ENTITY_TYPE_CONTAINER_CASE], opts);
};

export const addCase = async (context: AuthContext, user: AuthUser, caseManagement: CaseAddInput) => {
  const created = await createEntity(context, user, caseManagement, ENTITY_TYPE_CONTAINER_CASE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
