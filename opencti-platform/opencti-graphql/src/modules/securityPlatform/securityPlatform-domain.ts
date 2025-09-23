import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader'; import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntitySecurityPlatform, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from './securityPlatform-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById } from '../../database/middleware';
import type { SecurityPlatformAddInput } from '../../generated/graphql';

// region CRUD
export const findById = (context: AuthContext, user: AuthUser, securityPlatformId: string) => {
  return storeLoadById<BasicStoreEntitySecurityPlatform>(context, user, securityPlatformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
};

export const findSecurityPlatformPaginated = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntitySecurityPlatform>) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityPlatform>(context, user, [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM], args);
};

export const addSecurityPlatform = async (context: AuthContext, user: AuthUser, securityPlatform: SecurityPlatformAddInput) => {
  const securityPlatformWithClass = { identity_class: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM.toLowerCase(), ...securityPlatform };

  const created = await createEntity(context, user, securityPlatformWithClass, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const securityPlatformDelete = async (context: AuthContext, user: AuthUser, securityPlatformId: string) => {
  await deleteElementById(context, user, securityPlatformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, securityPlatformId, user);
  return securityPlatformId;
};

// endregion
