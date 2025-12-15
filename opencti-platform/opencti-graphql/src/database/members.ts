import { filterMembersUsersWithUsersOrgs } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity } from '../types/store';

export const loadCreators = async (
  context: AuthContext,
  user: AuthUser,
  object: BasicStoreEntity,
) => {
  const creators = await context.batch?.creatorsBatchLoader.load(object.creator_id);
  if (!creators) {
    return [];
  }
  return filterMembersUsersWithUsersOrgs(context, user, creators);
};
