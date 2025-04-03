import { uniq } from 'ramda';
import { isEmptyField } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicGroupEntity, BasicStoreEntity } from '../types/store';
import type { MemberAccess, MemberAccessInput, MemberGroupRestriction } from '../generated/graphql';
import {
  type AuthorizedMember,
  isUserHasCapabilities,
  isValidMemberAccessRight,
  MEMBER_ACCESS_ALL,
  MEMBER_ACCESS_CREATOR,
  MEMBER_ACCESS_RIGHT_ADMIN,
  SYSTEM_USER,
  validateUserAccessOperation
} from './access';
import { findAllMembers, findById as findUser } from '../domain/user';
import { findById as findGroup } from '../domain/group';
import { findById as findOrganization } from '../modules/organization/organization-domain';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { patchAttribute } from '../database/middleware';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS, isInternalObject } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/settings';
import { getDraftContext } from './draftContext';

export const getAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity
): Promise<MemberAccess[]> => {
  if (isEmptyField(entity.restricted_members)) {
    return [];
  }
  if (!validateUserAccessOperation(user, entity, 'manage-access')) {
    return []; // return empty if user doesn't have the right access_right
  }
  const entityRestrictedMembers = entity.restricted_members ?? [];
  const membersIds = entityRestrictedMembers.map((e) => e.id);
  const groupsRestrictionIds = entityRestrictedMembers.flatMap((e) => e.groups_restriction_ids ?? []);
  const args = {
    connectionFormat: false,
    first: 100,
    filters: {
      mode: 'and',
      filters: [{ key: 'internal_id', values: [...membersIds, ...groupsRestrictionIds] }],
      filterGroups: [],
    },
  };
  const members = await findAllMembers(context, user, args);
  return (entity.restricted_members ?? []).map((currentAuthMember, i) => {
    const member = members.find((m) => (m as BasicStoreEntity).id === currentAuthMember.id) as BasicStoreEntity;
    let groups_restriction: MemberGroupRestriction[] = [];
    if (currentAuthMember.groups_restriction_ids) {
      groups_restriction = currentAuthMember.groups_restriction_ids.map((groupId: string) => {
        const group = members.find((m) => (m as BasicStoreEntity).id === groupId) as BasicStoreEntity;
        return { id: groupId, name: group?.name ?? 'unknown' };
      });
    }
    return {
      id: `${currentAuthMember.id}_${i}`,
      member_id: currentAuthMember.id,
      name: member?.name ?? '',
      entity_type: member?.entity_type ?? '',
      access_right: currentAuthMember.access_right,
      groups_restriction
    };
  });
};

export const containsValidAdmin = async (
  context: AuthContext,
  authorized_members: Array<AuthorizedMember>,
  requiredCapabilities: string[] = []
) => {
  const adminIds = authorized_members
    .filter((n) => n.access_right === MEMBER_ACCESS_RIGHT_ADMIN)
    .map((e) => e.id);
  if (adminIds.length === 0) { // no admin
    return false;
  }
  if (adminIds.includes(MEMBER_ACCESS_ALL) || adminIds.includes(MEMBER_ACCESS_CREATOR)) { // everyone  or creator is admin
    return true;
  }
  // find the users that have admin rights
  const groups = (await Promise.all(adminIds.map((id) => findGroup(context, SYSTEM_USER, id))))
    .filter((n) => n) as BasicGroupEntity[];
  const organizations = (await Promise.all(adminIds.map((id) => findOrganization(context, SYSTEM_USER, id))))
    .filter((n) => n);
  const groupsMembersIds = uniq(groups.map((group) => group[RELATION_MEMBER_OF]).flat()) as string[];
  const organizationsMembersIds = uniq(organizations.map((o) => o[RELATION_PARTICIPATE_TO]).flat());
  const userIds = adminIds
    .filter((id) => !groups.map((o) => o.id).includes(id)
      && !organizations.map((o) => o.id).includes(id))
    .concat(groupsMembersIds, organizationsMembersIds);
  // resolve the users
  const users: (AuthUser | undefined)[] = await Promise.all(userIds.map((userId) => findUser(context, SYSTEM_USER, userId)));
  // restrict to the users that exist and have admin exploration capability
  const authorizedUsers = users.filter((u) => u && isUserHasCapabilities(u, requiredCapabilities));

  // at least 1 user with admin access and admin exploration capability
  return authorizedUsers.length > 0;
};

export const sanitizeAuthorizedMembers = (input: MemberAccessInput[]) => {
  return input.filter((value, index, array) => {
    if (!value.groups_restriction_ids) {
      return isValidMemberAccessRight(value.access_right) && array.findIndex((e) => e.id === value.id) === index;
    }

    return isValidMemberAccessRight(value.access_right) && array.findIndex((e) => e.id === value.id
      && e.groups_restriction_ids
      && e.groups_restriction_ids.length === value.groups_restriction_ids?.length
      && e.groups_restriction_ids.sort().join() === value.groups_restriction_ids.sort().join()) === index;
  });
};

export const editAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  args: {
    entityId: string,
    input: MemberAccessInput[] | undefined | null,
    requiredCapabilities: string[],
    entityType: string,
    busTopicKey?: keyof typeof BUS_TOPICS, // TODO improve busTopicKey types
  },
) => {
  if (getDraftContext(context, user)) throw UnsupportedError('Cannot edit authorized members in draft');
  const { entityId, input, requiredCapabilities, entityType, busTopicKey } = args;
  let restricted_members: { id: string, access_right: string, groups_restriction_ids: string[] | null | undefined }[] | null = null;

  if (input) {
    // validate input (validate access right) remove duplicate
    const filteredInput = sanitizeAuthorizedMembers(input);

    const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
    if (filteredInput.some(({ id }) => id === MEMBER_ACCESS_ALL) && settings.platform_organization && !isInternalObject(entityType)) {
      throw FunctionalError('You can\'t grant access to everyone in an organization sharing context');
    }

    const hasValidAdmin = await containsValidAdmin(
      context,
      filteredInput,
      requiredCapabilities,
    );
    if (!hasValidAdmin) {
      throw FunctionalError('It should have at least one valid member with admin access');
    }

    restricted_members = filteredInput.map(({ id, access_right, groups_restriction_ids }) => {
      const member = { id, access_right, groups_restriction_ids };
      if (!groups_restriction_ids) {
        delete member.groups_restriction_ids;
      }
      return member;
    });
  }

  const patch = { restricted_members };
  const { element } = await patchAttribute(context, user, entityId, entityType, patch);
  if (busTopicKey) {
    return notify(BUS_TOPICS[busTopicKey].EDIT_TOPIC, element, user);
  }
  return element;
};
