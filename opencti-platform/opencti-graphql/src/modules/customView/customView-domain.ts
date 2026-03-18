import type { AuthContext, AuthUser } from '../../types/user';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityCustomView, ENTITY_TYPE_CUSTOM_VIEW } from './customView-types';
import { createEntity, deleteElementById } from '../../database/middleware';
import type { CustomViewAddInput, QueryCustomViewArgs } from '../../generated/graphql';

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityCustomView> => {
  return storeLoadById(context, user, id, ENTITY_TYPE_CUSTOM_VIEW);
};

export const findCustomViewsPaginated = async (context: AuthContext, user: AuthUser, args: QueryCustomViewArgs) => {
  return pageEntitiesConnection<BasicStoreEntityCustomView>(context, user, [ENTITY_TYPE_CUSTOM_VIEW], args);
};

export const addCustomView = async (
  context: AuthContext,
  user: AuthUser,
  input: CustomViewAddInput,
) => {
  const customViewToCreate = {
    ...input,
  };

  return createEntity(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
  );
};

export const customViewDelete = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
) => {
  await deleteElementById(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
  );

  return customViewId;
};
