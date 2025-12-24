import { filterMembersUsersWithUsersOrgs } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity } from '../types/store';
import { loadThroughDenormalized } from '../resolvers/stix';
import { INPUT_ASSIGNEE, INPUT_PARTICIPANT } from '../schema/general';

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

export const loadCreator = async (
  context: AuthContext,
  user: AuthUser,
  userIdToLoad?: string,
) => {
  if (!userIdToLoad) return null;
  const realUser = await context.batch?.creatorBatchLoader.load(userIdToLoad);
  if (!realUser) return null;
  const filteredUser = await filterMembersUsersWithUsersOrgs(context, user, [realUser]);
  return filteredUser[0];
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

export const loadAssignees = async (
  context: AuthContext,
  user: AuthUser,
  object: BasicStoreEntity,
) => {
  const assignees = await loadThroughDenormalized(context, user, object, INPUT_ASSIGNEE, { sortBy: 'user_email' });
  if (!assignees) {
    return [];
  }
  return filterMembersUsersWithUsersOrgs(context, user, assignees);
};
