import { getEntitiesMapFromCache } from '../../database/cache';
import { INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { FunctionalError } from '../../config/errors';
import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';

/**
 * Resolves the real platform user configured for a public sharing endpoint (TAXII, CSV feed, stream).
 * Falls back to SYSTEM_USER if no userId is configured (backwards compatibility for existing collections).
 * Throws if the userId refers to an internal system user or no longer exists.
 */
export const resolvePublicUser = async (context: AuthContext, userId: string | null | undefined): Promise<AuthUser> => {
  if (!userId) {
    logApp.warn('[DATA_SHARING] No public user configured for this public sharing, falling back to SYSTEM_USER (deprecated - please configure a dedicated user)');
    return SYSTEM_USER;
  }
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
