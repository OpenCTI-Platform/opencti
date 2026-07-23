import { filterMembersUsersWithUsersOrgs, SYSTEM_USER } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreEntity } from '../types/store';
import { loadThroughDenormalized } from '../resolvers/stix';
import { INPUT_ASSIGNEE, INPUT_PARTICIPANT } from '../schema/general';
import type { Creator } from '../generated/graphql';
import { resolveMergeUsersPocAliasId } from '../utils/merge-users-poc-alias';
import { getEntitiesMapFromCache } from './cache';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { ConfigurationError } from '../config/errors';

const canonicalizeDisplayedMembers = async (
  context: AuthContext,
  members: BasicStoreEntity[],
): Promise<BasicStoreEntity[]> => {
  const canonicalIds = members.map((member) => resolveMergeUsersPocAliasId(member.internal_id));
  if (canonicalIds.every((id, index) => id === members[index].internal_id)) {
    return members;
  }
  const platformUsers = await getEntitiesMapFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const displayedMembers = canonicalIds.map((id, index) => {
    if (id === members[index].internal_id) {
      return members[index];
    }
    const target = platformUsers.get(id);
    if (!target) {
      throw ConfigurationError('MERGE_POC_ALIAS_MAP target user cannot be resolved', { id });
    }
    return target;
  });
  return [...new Map(displayedMembers.map((member) => [member.internal_id, member])).values()];
};

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
): Promise<Creator> => {
  const realUser = await context.batch?.creatorBatchLoader.load(userIdToLoad);
  if (!realUser) {
    return {
      ...SYSTEM_USER,
      representative: { main: SYSTEM_USER.name },
    };
  }
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
  const canonicalParticipants = await canonicalizeDisplayedMembers(context, participants);
  return filterMembersUsersWithUsersOrgs(context, user, canonicalParticipants);
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
  const canonicalAssignees = await canonicalizeDisplayedMembers(context, assignees);
  return filterMembersUsersWithUsersOrgs(context, user, canonicalAssignees);
};
