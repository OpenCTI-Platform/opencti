import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity } from '../types/store';
import type { MemberAccess } from '../generated/graphql';
import { validateUserAccessOperation } from '../utils/access';
import { findAllMembers } from './user';

export const getAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity & { authorized_members: Array<{ id: string, access_right: string }> }
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
