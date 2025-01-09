import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { QueryDisseminationListsArgs } from '../../generated/graphql';
import { type BasicStoreEntityDisseminationList, ENTITY_TYPE_DISSEMINATION_LIST } from './disseminationList-types';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDisseminationList>(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDisseminationListsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDisseminationList>(context, user, [ENTITY_TYPE_DISSEMINATION_LIST], args);
};

// export const addDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListAddInput) => {};
// export const fieldPatchDisseminationList = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {};
// export const deleteDisseminationList = async (context: AuthContext, user: AuthUser, id: string) => {};
