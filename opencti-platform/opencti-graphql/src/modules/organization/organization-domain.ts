import { batchListThroughGetFrom, batchListThroughGetTo, createEntity, patchAttribute } from '../../database/middleware';
import { type EntityOptions, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { notify } from '../../database/redis';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../../schema/stixDomainObject';
import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from './organization-types';
import type { AuthContext, AuthUser } from '../../types/user';
import type { OrganizationAddInput } from '../../generated/graphql';

// region CRUD
export const findById = (context: AuthContext, user: AuthUser, organizationId: string) => {
  return storeLoadById<BasicStoreEntityOrganization>(context, user, organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};

export const findAll = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntityOrganization>) => {
  // TODO add include_authorized_authorities to filter
  return listEntitiesPaginated<BasicStoreEntityOrganization>(context, user, [ENTITY_TYPE_IDENTITY_ORGANIZATION], args);
};

export const addOrganization = async (context: AuthContext, user: AuthUser, organization: OrganizationAddInput) => {
  const organizationWithClass = { identity_class: ENTITY_TYPE_IDENTITY_ORGANIZATION.toLowerCase(), ...organization };
  const created = await createEntity(context, user, organizationWithClass, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
export const editAuthorizedAuthorities = async (context: AuthContext, user: AuthUser, organizationId: string, input: string[]) => {
  const patch = { authorized_authorities: input };
  const { element } = await patchAttribute(context, user, organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION, patch);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, element, user);
};
// endregion

// region BATCH
export const batchSectors = (context: AuthContext, user: AuthUser, organizationIds: string[]) => {
  return batchListThroughGetTo(context, user, organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};
export const batchMembers = async (context: AuthContext, user: AuthUser, organizationIds: string[], opts = {}) => {
  // TODO Add restriction in case we remove the @auth
  return batchListThroughGetFrom(context, user, organizationIds, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER, opts);
};
export const batchSubOrganizations = async (context: AuthContext, user: AuthUser, organizationIds: string[], opts = {}) => {
  return batchListThroughGetFrom(context, user, organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, opts);
};
export const batchParentOrganizations = async (context: AuthContext, user: AuthUser, organizationIds: string[], opts = {}) => {
  return batchListThroughGetTo(context, user, organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, opts);
};
// endregion
