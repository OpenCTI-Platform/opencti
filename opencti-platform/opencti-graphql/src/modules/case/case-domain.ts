import type { AuthContext, AuthUser } from '../../types/user';
import { BasicStoreEntityCase, ENTITY_TYPE_CONTAINER_CASE, } from './case-types';
import type { EntityOptions } from '../../database/middleware-loader';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';

export const findById = (context: AuthContext, user: AuthUser, caseId: string): BasicStoreEntityCase => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE) as unknown as BasicStoreEntityCase;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCase>) => {
  return listEntitiesPaginated<BasicStoreEntityCase>(context, user, [ENTITY_TYPE_CONTAINER_CASE], opts);
};
