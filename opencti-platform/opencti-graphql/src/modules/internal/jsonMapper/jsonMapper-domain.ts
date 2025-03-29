import type { AuthContext, AuthUser } from '../../../types/user';
import { storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityJsonMapper, ENTITY_TYPE_JSON_MAPPER } from './jsonMapper-types';
import type { QueryJsonMappersArgs } from '../../../generated/graphql';
import { testIngestion } from '../../../manager/ingestionManager';

export const findById = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  return storeLoadById<BasicStoreEntityJsonMapper>(context, user, csvMapperId, ENTITY_TYPE_JSON_MAPPER);
};

export const findAll = (_context: AuthContext, _user: AuthUser, _opts: QueryJsonMappersArgs) => {
  // return listEntitiesPaginated<BasicStoreEntityJsonMapper>(context, user, [ENTITY_TYPE_JSON_MAPPER], opts);
  return {
    edges: [{
      node: testIngestion
    }]
  };
};
