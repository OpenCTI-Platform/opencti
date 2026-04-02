import { getEntitiesMapFromCache } from '../../database/cache';
import { INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { DatabaseError, FunctionalError } from '../../config/errors';
import { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import { elRawUpdateByQuery } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { ENTITY_TYPE_FEED } from './feed-types';
import { ENTITY_TYPE_TAXII_COLLECTION } from './taxiiCollection-types';
import { ENTITY_TYPE_STREAM_COLLECTION } from './streamCollection-types';

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

type SharingConfig = {
  entityType: string;
  publicField: string;
  userIdField: string;
  liveField?: string;
};

const PUBLIC_SHARING_CONFIGS: SharingConfig[] = [
  { entityType: ENTITY_TYPE_FEED, publicField: 'feed_public', userIdField: 'feed_public_user_id' },
  { entityType: ENTITY_TYPE_TAXII_COLLECTION, publicField: 'taxii_public', userIdField: 'taxii_public_user_id' },
  { entityType: ENTITY_TYPE_STREAM_COLLECTION, publicField: 'stream_public', userIdField: 'stream_public_user_id', liveField: 'stream_live' },
];

/**
 * When a user is deleted, disables all public sharing entities (CSV feed, TAXII collection, live stream)
 * that referenced that user as their public impersonation user.
 * The public flag is set to false, stream_live is set to false for streams, and the user id field is cleared.
 */
export const disablePublicSharingForDeletedUser = async (context: AuthContext, userId: string): Promise<void> => {
  await Promise.all(
    PUBLIC_SHARING_CONFIGS.map(({ entityType, publicField, userIdField, liveField }) => {
      const liveScript = liveField ? ` ctx._source.${liveField} = false;` : '';
      return elRawUpdateByQuery({
        index: READ_INDEX_INTERNAL_OBJECTS,
        refresh: true,
        body: {
          script: {
            source: `ctx._source.${publicField} = false;${liveScript} ctx._source.remove('${userIdField}');`,
            lang: 'painless',
          },
          query: {
            bool: {
              must: [
                { term: { 'entity_type.keyword': { value: entityType } } },
                { term: { [`${userIdField}.keyword`]: { value: userId } } },
              ],
            },
          },
        },
      }).catch((err: Error) => {
        throw DatabaseError(`[DATA_SHARING] Error disabling public sharing for deleted user on ${entityType}`, { cause: err, userId });
      });
    }),
  );
  logApp.info('[DATA_SHARING] Disabled public sharing for all entities referencing deleted user', { userId });
};
