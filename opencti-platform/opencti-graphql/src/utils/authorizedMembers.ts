import { uniq } from 'ramda';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicGroupEntity, BasicOrganizationEntity, BasicStoreEntity } from '../types/store';
import type { MemberAccess } from '../generated/graphql';
import {
  AuthorizedMember,
  BYPASS,
  MEMBER_ACCESS_ALL,
  MEMBER_ACCESS_RIGHT_ADMIN,
  SYSTEM_USER,
  validateUserAccessOperation
} from './access';
import { findAllMembers, findById as findUser } from '../domain/user';
import { findById as findGroup } from '../domain/group';
import { findById as findOrganization } from '../domain/organization';
import { RELATION_MEMBER_OF, RELATION_PARTICIPATE_TO } from '../schema/internalRelationship';

export const getAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity & { authorized_members: Array<AuthorizedMember> }
): Promise<MemberAccess[]> => {
  let authorizedMembers: MemberAccess[] = [];
  if (!entity.authorized_members?.length) {
    return authorizedMembers;
  }
  if (!validateUserAccessOperation(user, entity, 'manage-access')) {
    return authorizedMembers; // return empty if user doesn't have the right access_right
  }
  const membersIds = entity.authorized_members.map((e) => e.id);
  const args = {
    connectionFormat: false,
    first: 100,
    filters: [{ key: 'internal_id', values: membersIds }],
  };
  const members = await findAllMembers(context, user, args);
  authorizedMembers = entity.authorized_members.map((am) => {
    const member = members.find((m) => (m as BasicStoreEntity).id === am.id) as BasicStoreEntity;
    return { id: am.id, name: member?.name ?? '', entity_type: member?.entity_type ?? '', access_right: am.access_right };
  });
  return authorizedMembers;
};

const hasExplorationCapabilities = (u: AuthUser) => {
  const userCapabilities = u.capabilities.map((n) => n.name);
  return userCapabilities.includes(BYPASS)
    || (userCapabilities.includes('EXPLORE_EXUPDATE_EXDELETE') && userCapabilities.includes('EXPLORE_EXUPDATE'));
};

export const containsValidAdmin = async (
  context: AuthContext,
  authorized_members: Array<AuthorizedMember>,
) => {
  const adminIds = authorized_members
    .filter((n) => n.access_right === MEMBER_ACCESS_RIGHT_ADMIN)
    .map((e) => e.id);
  if (adminIds.length === 0) { // no admin
    return false;
  }
  if (adminIds.includes(MEMBER_ACCESS_ALL)) { // everyone is admin
    return true;
  }
  // find the users that have admin rights
  const groups = (await Promise.all(adminIds.map((id) => findGroup(context, SYSTEM_USER, id))))
    .filter((n) => n) as BasicGroupEntity[];
  const organizations = (await Promise.all(adminIds.map((id) => findOrganization(context, SYSTEM_USER, id))))
    .filter((n) => n) as BasicOrganizationEntity[];
  const groupsMembersIds = uniq(groups.map((group) => group[RELATION_MEMBER_OF]).flat()) as string[];
  const organizationsMembersIds = uniq(organizations.map((o) => o[RELATION_PARTICIPATE_TO]).flat());
  const userIds = adminIds
    .filter((id) => !groups.map((o) => o.id).includes(id)
      && !organizations.map((o) => o.id).includes(id))
    .concat(groupsMembersIds, organizationsMembersIds);
  // resolve the users
  const users: (AuthUser | undefined)[] = await Promise.all(userIds.map((userId) => findUser(context, SYSTEM_USER, userId)));
  // restrict to the users that exist and have admin exploration capability
  const authorizedUsers = users.filter((u) => u && hasExplorationCapabilities(u));
  if (authorizedUsers.length > 0) { // at least 1 user with admin access and admin exploration capability
    return true;
  }
  return false;
};
