import { filterMembersUsersWithUsersOrgs } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity } from '../types/store';
import { loadThroughDenormalized } from '../resolvers/stix';
import { INPUT_PARTICIPANT } from '../schema/general';

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

export const loadParticipants = async (
  context: AuthContext,
  user: AuthUser,
  object: BasicStoreEntity,
) => {
  const participants = await loadThroughDenormalized(context, user, object, INPUT_PARTICIPANT, { sortBy: 'user_email' });
  if (!participants) {
    return [];
  }
  return filterMembersUsersWithUsersOrgs(context, user, participants);
};
