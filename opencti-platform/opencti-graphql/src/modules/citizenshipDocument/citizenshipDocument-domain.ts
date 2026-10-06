import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityCitizenshipDocument, ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT } from './citizenshipDocument-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById } from '../../database/middleware';
import type { CitizenshipDocumentAddInput } from '../../generated/graphql';

// region CRUD
export const findById = (context: AuthContext, user: AuthUser, citizenshipDocumentId: string) => {
  return storeLoadById<BasicStoreEntityCitizenshipDocument>(context, user, citizenshipDocumentId, ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT);
};

export const findCitizenshipDocumentPaginated = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntityCitizenshipDocument>) => {
  return pageEntitiesConnection<BasicStoreEntityCitizenshipDocument>(context, user, [ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT], args);
};

export const addCitizenshipDocument = async (context: AuthContext, user: AuthUser, citizenshipDocument: CitizenshipDocumentAddInput) => {
  const citizenshipDocumentWithClass = { identity_class: ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT.toLowerCase(), ...citizenshipDocument };

  const created = await createEntity(context, user, citizenshipDocumentWithClass, ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const citizenshipDocumentDelete = async (context: AuthContext, user: AuthUser, citizenshipDocumentId: string) => {
  await deleteElementById(context, user, citizenshipDocumentId, ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, citizenshipDocumentId, user);
  return citizenshipDocumentId;
};

// endregion
