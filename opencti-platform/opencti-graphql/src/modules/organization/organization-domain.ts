import { batchListThroughGetFrom, batchListThroughGetTo, createEntity, patchAttribute } from '../../database/middleware';
import { type EntityOptions, internalFindByIds, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
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
import { FunctionalError } from '../../config/errors';
import { isUserHasCapability, SETTINGS_SET_ACCESSES } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';

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

export const organizationAdminAdd = async (context: AuthContext, user: AuthUser, organizationId: string, memberId: string) => {
  // Get Orga and members
  const organization = await findById(context, user, organizationId);
  const members = await batchListThroughGetFrom(context, user, organizationId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER, { batched: false, paginate: false });
  const updatedUser = members.find(({ id }) => id === memberId);
  // Check if user is part of Orga. If not, throw exception
  if (!updatedUser) {
    throw FunctionalError('User is not part of the organization');
  }
  // Add user to organization admins list
  const updated = await editAuthorizedAuthorities(context, user, organizationId, [...(organization.authorized_authorities ?? []), memberId]);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `Promoting \`${updatedUser.name}\` as admin orga of \`${organization.name}\``,
    context_data: { entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, input: { organizationId, memberId } }
  });
  return updated;
};

export const organizationAdminRemove = async (context: AuthContext, user: AuthUser, organizationId: string, memberId: string) => {
  // Get Orga and members
  const organization = await findById(context, user, organizationId);
  const members = await batchListThroughGetFrom(context, user, organizationId, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER, { batched: false, paginate: false });

  // Check if user is part of Orga and is orga_admin. If not, throw exception
  if (!members.map((m) => m.id).includes(memberId)) {
    throw FunctionalError('User is not part of the organization');
  }
  // Remove user from organization admins list
  const indexOfMember = (organization.authorized_authorities ?? []).indexOf(memberId);
  (organization.authorized_authorities ?? []).splice(indexOfMember, 1);
  const updated = await editAuthorizedAuthorities(context, user, organizationId, (organization.authorized_authorities ?? []));
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `Demoting \`${updatedUser.name}\` as admin orga of \`${organization.name}\``,
    context_data: { entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, input: { organizationId, memberId } }
  });
  return updated;
};

export const findGrantableGroups = async (context: AuthContext, user: AuthUser, organization) => {
  return internalFindByIds(context, user, organization.grantable_groups);
};
// endregion

// region BATCH
export const batchSectors = (context: AuthContext, user: AuthUser, organizationIds: string[]) => {
  return batchListThroughGetTo(context, user, organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_SECTOR);
};
export const batchMembers = async (context: AuthContext, user: AuthUser, organizationIds: string[], opts = {}) => {
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    // TODO return filtered list
  }
  return batchListThroughGetFrom(context, user, organizationIds, RELATION_PARTICIPATE_TO, ENTITY_TYPE_USER, opts);
};
export const batchSubOrganizations = async (context: AuthContext, user: AuthUser, organizationIds: string[], opts = {}) => {
  return batchListThroughGetFrom(context, user, organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, opts);
};
export const batchParentOrganizations = async (context: AuthContext, user: AuthUser, organizationIds: string[], opts = {}) => {
  return batchListThroughGetTo(context, user, organizationIds, RELATION_PART_OF, ENTITY_TYPE_IDENTITY_ORGANIZATION, opts);
};
// endregion
