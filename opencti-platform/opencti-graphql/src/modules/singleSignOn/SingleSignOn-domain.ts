import type { AuthContext, AuthUser } from '../../types/user';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_SINGLE_SIGN_ON, type BasicStoreEntitySingleSignOn, type StoreEntitySingleSignOn } from "./SingleSignOn-types";
import type { SingleSignOnInput } from '../../generated/graphql';
import { EditInput } from '../../generated/graphql';
import { now } from '../../utils/format';
import { createInternalObject } from '../../domain/internalObject';
import {FunctionalError, UnsupportedError} from '../../config/errors';
import { deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, isFeatureEnabled } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';

const isSingleSignOnEnabled = isFeatureEnabled('SINGLE_SIGN_ON_ENABLED');

export const findSingleSignOnById = (context: AuthContext, user: AuthUser, id: string) => {
  if (!isSingleSignOnEnabled) throw UnsupportedError('Feature not yet available');
  return storeLoadById<BasicStoreEntitySingleSignOn>(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON);
}

export const findSingleSignOnPaginated = (context: AuthContext, user: AuthUser, args: any) => {
  if (!isSingleSignOnEnabled) throw UnsupportedError('Feature not yet available');
  return pageEntitiesConnection<BasicStoreEntitySingleSignOn>(context, user, [ENTITY_TYPE_SINGLE_SIGN_ON], args);
}

export const addSingleSignOn = (context: AuthContext, user: AuthUser, input: SingleSignOnInput) => {
  if (!isSingleSignOnEnabled) throw UnsupportedError('Feature not yet available');
  const defaultOps = { created_at: now(), updated_at: now() };
  const singleSignOnInput = { ...input, ...defaultOps };
  return createInternalObject<StoreEntitySingleSignOn>(context, user, singleSignOnInput, ENTITY_TYPE_SINGLE_SIGN_ON);
}

export const fieldPatchSingleSignOn = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  if (!isSingleSignOnEnabled) throw UnsupportedError('Feature not yet available');
  const singleSignOn = await findSingleSignOnById<StoreEntitySingleSignOn>(context, user, id);

  if (!singleSignOn) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for single sign on \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input },
  });

  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
}

export const deleteSingleSignOn = async (context: AuthContext, user: AuthUser, id: string) => {
  if (!isSingleSignOnEnabled) throw UnsupportedError('Feature not yet available');
  const singleSignOn = await findSingleSignOnById<StoreEntitySingleSignOn>(context, user, id);

  if (!singleSignOn) {
    throw FunctionalError(`Single sign on ${id} cannot be found`);
  }

  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_SINGLE_SIGN_ON);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes decay exclusion rule \`${deleted.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_SINGLE_SIGN_ON, input: deleted },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, singleSignOn, user);
  return id;
}