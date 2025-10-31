import { getEntityFromCache } from './cache';
import { FunctionalError } from '../config/errors';
import { FilterMode } from '../generated/graphql';
import { countAllThings, pageRegardingEntitiesConnection } from './middleware-loader';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../schema/stixDomainObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity, StoreObject } from '../types/store';
import type { BasicStoreSettings } from '../types/settings';
import { isEmptyField, READ_INDEX_INTERNAL_OBJECTS } from './utils';
import { isUserHasCapability, SETTINGS_SET_ACCESSES, SYSTEM_USER } from '../utils/access';

export const isIndividualAssociatedToUser = async (context: AuthContext, individual: BasicStoreEntity) => {
  const individualContactInformation = individual.contact_information;
  if (isEmptyField(individualContactInformation)) {
    return false;
  }
  const args = {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['user_email'], values: [individualContactInformation] }],
      filterGroups: [],
    },
    noFiltersChecking: true,
    indices: [READ_INDEX_INTERNAL_OBJECTS],
  };
  const usersCount = await countAllThings(context, SYSTEM_USER, args);
  return usersCount > 0;
};

export const verifyCanDeleteIndividual = async (context: AuthContext, user: AuthUser, individual: BasicStoreEntity, throwErrors = true) => {
  const isAssociatedToUser = await isIndividualAssociatedToUser(context, individual);
  if (isAssociatedToUser) {
    if (throwErrors) throw FunctionalError('Cannot delete an individual corresponding to a user', { id: individual.id });
    return false;
  }
  return true;
};

export const verifyCanDeleteOrganization = async (context: AuthContext, user: AuthUser, organization: BasicStoreEntityOrganization, throwErrors = true) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  if (organization.id === settings.platform_organization) {
    if (throwErrors) throw FunctionalError('Cannot delete the platform organization.');
    return false;
  }
  if (organization.authorized_authorities && organization.authorized_authorities.length > 0) {
    if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
      if (throwErrors) throw FunctionalError('Cannot delete an organization that has an administrator.', { id: organization.id });
      return false;
    }
    // no information leakage about the organization administrators or members
    if (throwErrors) throw FunctionalError('Cannot delete the organization.', { id: organization.id });
    return false;
  }
  // organizationMembersPaginated
  const members = await pageRegardingEntitiesConnection(
    context,
    user,
    organization.id,
    RELATION_PARTICIPATE_TO,
    ENTITY_TYPE_USER,
    true,
    { first: 1, indices: [READ_INDEX_INTERNAL_OBJECTS] }
  );
  if (members.pageInfo.globalCount > 0) {
    if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
      if (throwErrors) throw FunctionalError('Cannot delete an organization that has members.', { id: organization.id });
      return false;
    }
    // no information leakage about the organization administrators or members
    if (throwErrors) throw FunctionalError('Cannot delete the organization.', { id: organization.id });
    return false;
  }
  return true;
};

export const canDeleteElement = async (context: AuthContext, user: AuthUser, element: StoreObject) => {
  if (element.entity_type === ENTITY_TYPE_IDENTITY_INDIVIDUAL) {
    return verifyCanDeleteIndividual(context, user, element as BasicStoreEntity, false);
  }
  if (element.entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
    return verifyCanDeleteOrganization(context, user, element as unknown as BasicStoreEntityOrganization, false);
  }
  return true;
};
