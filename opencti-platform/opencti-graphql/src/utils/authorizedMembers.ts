import { uniq } from 'ramda';
import { isEmptyField } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicGroupEntity, BasicStoreEntity } from '../types/store';
import type { MemberAccess, MemberAccessInput } from '../generated/graphql';
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
  let authorizedMembers: MemberAccess[] = [];
  if (isEmptyField(entity.authorized_members)) {
    return authorizedMembers;
  }
  if (!validateUserAccessOperation(user, entity, 'manage-access')) {
    return authorizedMembers; // return empty if user doesn't have the right access_right
  }
  const membersIds = (entity.authorized_members ?? []).map((e) => e.id);
  const args = {
    connectionFormat: false,
    first: 100,
    filters: {
      mode: 'and',
      filters: [{ key: 'internal_id', values: membersIds }],
      filterGroups: [],
    },
  };
  const members = await findAllMembers(context, user, args);
  authorizedMembers = (entity.authorized_members ?? []).map((am) => {
    const member = members.find((m) => (m as BasicStoreEntity).id === am.id) as BasicStoreEntity;
    return { id: am.id, name: member?.name ?? '', entity_type: member?.entity_type ?? '', access_right: am.access_right };
  });
  return authorizedMembers;
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
  let authorized_members: { id: string, access_right: string }[] | null = null;

  if (input) {
    // validate input (validate access right) and remove duplicates
    const filteredInput = input.filter((value, index, array) => {
      return isValidMemberAccessRight(value.access_right) && array.findIndex((e) => e.id === value.id) === index;
    });

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

    authorized_members = filteredInput.map(({ id, access_right }) => ({ id, access_right }));
  }

  const patch = { authorized_members };
  const { element } = await patchAttribute(context, user, entityId, entityType, patch);
  if (busTopicKey) {
    return notify(BUS_TOPICS[busTopicKey].EDIT_TOPIC, element, user);
  }
  return element;
};
