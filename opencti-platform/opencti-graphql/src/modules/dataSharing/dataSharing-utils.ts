import { getEntitiesMapFromCache } from '../../database/cache';
import { INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { FunctionalError } from '../../config/errors';
import { BUS_TOPICS, logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList } from '../../database/middleware-loader';
import { patchAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { FilterMode } from '../../generated/graphql';
import type { BasicStoreEntity } from '../../types/store';
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
  entityLabel: string;
};

const PUBLIC_SHARING_CONFIGS: SharingConfig[] = [
  { entityType: ENTITY_TYPE_FEED, publicField: 'feed_public', userIdField: 'feed_public_user_id', entityLabel: 'csv feed' },
  { entityType: ENTITY_TYPE_TAXII_COLLECTION, publicField: 'taxii_public', userIdField: 'taxii_public_user_id', entityLabel: 'Taxii collection' },
  { entityType: ENTITY_TYPE_STREAM_COLLECTION, publicField: 'stream_public', userIdField: 'stream_public_user_id', liveField: 'stream_live', entityLabel: 'live stream' },
];

/**
 * When a user is deleted, disables all public sharing entities (CSV feed, TAXII collection, live stream)
 * that referenced that user as their public impersonation user.
 * The public flag is set to false, stream_live is set to false for streams, and the user id field is cleared.
 * The cache is invalidated via notify for each updated entity.
 */
export const disablePublicSharingForDeletedUser = async (context: AuthContext, userId: string): Promise<void> => {
  await Promise.all(
    PUBLIC_SHARING_CONFIGS.map(async ({ entityType, publicField, userIdField, liveField, entityLabel }) => {
      const filters = {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [{ key: [userIdField], values: [userId] }],
      };
      const entities = await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [entityType], { filters });
      if (entities.length === 0) return;

      await Promise.all(
        entities.map(async (entity) => {
          // Log 1 (streams only): stop the live stream
          if (liveField) {
            const { element: liveElement } = await patchAttribute(context, SYSTEM_USER, entity.id, entityType, { [liveField]: false });
            await publishUserAction({
              user: SYSTEM_USER,
              event_type: 'mutation',
              event_scope: 'update',
              event_access: 'administration',
              message: `updates \`${liveField}\` for ${entityLabel} \`${entity.name}\``,
              context_data: { id: entity.id, entity_type: entityType, input: [{ key: liveField, value: ['false'] }] },
            });
            await notify(BUS_TOPICS[ENTITY_TYPE_STREAM_COLLECTION].EDIT_TOPIC, liveElement, SYSTEM_USER);
          }

          // Log 2: make it private and clear the user id
          const publicPatch: Record<string, string | boolean | null> = { [publicField]: false, [userIdField]: null };
          const operations: Record<string, 'replace' | 'remove'> = { [userIdField]: 'remove' };
          const { element } = await patchAttribute(context, SYSTEM_USER, entity.id, entityType, publicPatch, { operations });
          await publishUserAction({
            user: SYSTEM_USER,
            event_type: 'mutation',
            event_scope: 'update',
            event_access: 'administration',
            message: `updates \`${publicField}\` for ${entityLabel} \`${entity.name}\``,
            context_data: { id: entity.id, entity_type: entityType, input: [{ key: publicField, value: ['false'] }] },
          });
          const busTopic = (BUS_TOPICS as Record<string, { EDIT_TOPIC?: string } | undefined>)[entityType];
          if (busTopic?.EDIT_TOPIC) {
            await notify(busTopic.EDIT_TOPIC, element, SYSTEM_USER);
          }
        }),
      );
    }),
  );
  logApp.info('[DATA_SHARING] Disabled public sharing for all entities referencing deleted user', { userId });
};
