import type { AuthContext, AuthUser } from '../../../types/user';
import { listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityJsonMapper, ENTITY_TYPE_JSON_MAPPER } from './jsonMapper-types';
import type { QueryJsonMappersArgs } from '../../../generated/graphql';

export const findById = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  return storeLoadById<BasicStoreEntityJsonMapper>(context, user, csvMapperId, ENTITY_TYPE_JSON_MAPPER);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryJsonMappersArgs) => {
  return listEntitiesPaginated<BasicStoreEntityJsonMapper>(context, user, [ENTITY_TYPE_JSON_MAPPER], opts);
};
