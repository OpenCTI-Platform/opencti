import { getEntitiesMapFromCache } from '../../database/cache';
import { INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { FunctionalError } from '../../config/errors';
import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';

/**
 * Internal helper: fetches and validates a non-internal, existing platform user from cache.
 * Throws if the userId refers to an internal system user or no longer exists.
 */
const resolveValidUser = async (context: AuthContext, userId: string): Promise<AuthUser> => {
  if (INTERNAL_USERS[userId]) {
    throw FunctionalError('Cannot use an internal system user for public sharing', { userId });
  }
  const platformUsersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const user = platformUsersMap.get(userId);
  if (!user) {
    throw FunctionalError('The user configured for this public sharing no longer exists', { userId });
  }
  return user;
};

/**
 * Validates that the given userId is a valid, non-internal platform user.
 * Intended to be called at write time (create/edit) to reject invalid user IDs early.
 */
export const validatePublicUserId = async (context: AuthContext, userId: string): Promise<void> => {
  await resolveValidUser(context, userId);
};

/**
 * Resolves the platform user to use when serving a public sharing endpoint (TAXII, CSV feed, stream).
 * Falls back to SYSTEM_USER for existing collections that predate the public user feature (backwards compatibility).
 */
export const resolvePublicUser = async (context: AuthContext, userId: string | null | undefined): Promise<AuthUser> => {
  if (!userId) {
    logApp.warn('[DATA_SHARING] No public user configured for this public sharing, falling back to SYSTEM_USER (deprecated - please configure a dedicated user)');
    return SYSTEM_USER;
  }
  return resolveValidUser(context, userId);
};
