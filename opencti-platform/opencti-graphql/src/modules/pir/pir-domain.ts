import type { AuthContext, AuthUser } from '../../types/user';
import { type EntityOptions, listEntitiesPaginated } from '../../database/middleware-loader';
import { type BasicStoreEntityPIR, ENTITY_TYPE_PIR } from './pir-types';

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityPIR>) => {
  return listEntitiesPaginated<BasicStoreEntityPIR>(context, user, [ENTITY_TYPE_PIR], opts);
};

export const pirAdd = async (context: AuthContext, user: AuthUser) => {
  return null;
};
