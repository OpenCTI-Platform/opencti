import type { AuthContext, AuthUser } from '../../types/user';
import { storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityCustomView, ENTITY_TYPE_CUSTOM_VIEW } from './customView-types';
import { createEntity, deleteElementById } from '../../database/middleware';
import type { CustomViewAddInput } from '../../generated/graphql';

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityCustomView> => {
  return storeLoadById(context, user, id, ENTITY_TYPE_CUSTOM_VIEW);
};

export const addCustomView = async (
  context: AuthContext,
  user: AuthUser,
  input: CustomViewAddInput,
) => {
  const customViewToCreate = {
    name: input.name,
    description: input.description ?? '',
    manifest: input.manifest ?? '',
    authorizedMembers: input.authorizedMembers ?? [],
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
