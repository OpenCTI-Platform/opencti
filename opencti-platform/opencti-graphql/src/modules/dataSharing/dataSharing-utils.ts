import { LRUCache } from 'lru-cache';
import { getEntitiesMapFromCache } from '../../database/cache';
import { INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { booleanConf, BUS_TOPICS, logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList } from '../../database/middleware-loader';
import { patchAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { type EditInput, FilterMode } from '../../generated/graphql';
import { booleanTrueFilter } from '../../utils/filtering/filtering-utils';
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

type PublicUserIdField = 'feed_public_user_id' | 'taxii_public_user_id' | 'stream_public_user_id';

type SharingConfig = {
  entityType: string;
  publicField: 'feed_public' | 'taxii_public' | 'stream_public';
  userIdField: PublicUserIdField;
  liveField?: string;
  entityLabel: string;
};

const PUBLIC_SHARING_CONFIGS: SharingConfig[] = [
  { entityType: ENTITY_TYPE_FEED, publicField: 'feed_public', userIdField: 'feed_public_user_id', entityLabel: 'csv feed' },
  { entityType: ENTITY_TYPE_TAXII_COLLECTION, publicField: 'taxii_public', userIdField: 'taxii_public_user_id', entityLabel: 'Taxii collection' },
  { entityType: ENTITY_TYPE_STREAM_COLLECTION, publicField: 'stream_public', userIdField: 'stream_public_user_id', liveField: 'stream_live', entityLabel: 'live stream' },
];

// A CSV feed, TAXII collection or live stream, as stored
export type PublicSharingEntity = Pick<BasicStoreEntity, 'id' | 'entity_type'> & {
  name: string;
  feed_public?: boolean | null;
  taxii_public?: boolean | null;
  stream_public?: boolean | null;
} & Partial<Record<PublicUserIdField, string | null>>;

type PublicSharingSummary = { entity_type: string; id: string; name: string };

const summarizeSharing = (sharing: PublicSharingEntity): PublicSharingSummary => {
  return { entity_type: sharing.entity_type, id: sharing.id, name: sharing.name };
};

const getSharingConfig = (entityType: string): SharingConfig => {
  const config = PUBLIC_SHARING_CONFIGS.find((c) => c.entityType === entityType);
  if (!config) {
    throw FunctionalError('Unsupported public sharing type', { entity_type: entityType });
  }
  return config;
};

// Secure by default: once true, a public sharing without a public user is refused instead of being served as SYSTEM_USER.
// Read on each call, so that the tests can switch it.
const isDataSharingSecureByDefault = (): boolean => booleanConf('app:data_sharing:secure_by_default', false);

// A public sharing is requested again and again (TAXII polling, feed pulls, stream reconnections): warn once an hour per collection and node
const publicSharingWarnings = new LRUCache<string, true>({ max: 1000, ttl: 60 * 60 * 1000 });

const warnOncePerSharing = (sharing: PublicSharingEntity, message: string) => {
  if (!publicSharingWarnings.has(sharing.id)) {
    publicSharingWarnings.set(sharing.id, true);
    logApp.warn(message, summarizeSharing(sharing));
  }
};

/** @internal Test-only: forgets the collections already warned about */
export const resetPublicSharingWarnings = () => publicSharingWarnings.clear();

/**
 * Resolves the platform user to use when serving a public sharing endpoint (TAXII, CSV feed, stream).
 * A public sharing that predates the public user feature has none: it is served as SYSTEM_USER while
 * app:data_sharing:secure_by_default is false, and refused once it is true.
 */
export const resolvePublicUser = async (context: AuthContext, sharing: PublicSharingEntity): Promise<AuthUser> => {
  const { userIdField, entityLabel } = getSharingConfig(sharing.entity_type);
  const userId = sharing[userIdField];
  if (userId) {
    return resolveValidUser(context, userId);
  }
  if (isDataSharingSecureByDefault()) {
    warnOncePerSharing(sharing, `[DATA_SHARING] The public ${entityLabel} has no public user and is refused (app:data_sharing:secure_by_default=true): configure a public user on it to serve it.`);
    // The id, not the name: the message is also the reason phrase of the live stream answer, which only takes latin-1
    throw ForbiddenAccess(`The public ${entityLabel} ${sharing.id} has no public user: an administrator must configure one to serve it`);
  }
  warnOncePerSharing(sharing, `[DATA_SHARING] The public ${entityLabel} has no public user and is served with full access to the platform data (app:data_sharing:secure_by_default=false). `
  + 'It will be refused in an upcoming version: configure a public user on it, then set APP__DATA_SHARING__SECURE_BY_DEFAULT=true to opt in now.');
  return SYSTEM_USER;
};

const isTrueValue = (value: unknown) => value === true || value === 'true';

/**
 * Whether a field patch would leave a public sharing without a public user: when it makes it public, or clears its public user.
 * The stored sharing is only loaded when the patch touches one of these fields.
 */
export const isPublicUserMissingAfterEdit = async (
  entityType: string,
  input: EditInput[],
  loadSharing: () => Promise<PublicSharingEntity | undefined>,
): Promise<boolean> => {
  const { publicField, userIdField } = getSharingConfig(entityType);
  const publicItem = input.find((item) => item.key === publicField);
  const userIdItem = input.find((item) => item.key === userIdField);
  const setsPublic = isTrueValue(publicItem?.value?.[0]);
  if (!setsPublic && !userIdItem) {
    return false;
  }
  const sharing = await loadSharing();
  const isPublic = publicItem ? setsPublic : !!sharing?.[publicField];
  const userId = userIdItem ? userIdItem.value?.[0] : sharing?.[userIdField];
  return isPublic && !userId;
};

// Lists the public sharings (CSV feed, TAXII collection, live stream) that have no public user
export const findPublicSharingsWithoutUser = async (context: AuthContext): Promise<PublicSharingSummary[]> => {
  const sharingsByType = await Promise.all(
    PUBLIC_SHARING_CONFIGS.map(async ({ entityType, publicField, userIdField }) => {
      const sharings = await fullEntitiesList<BasicStoreEntity & PublicSharingEntity>(context, SYSTEM_USER, [entityType], { filters: booleanTrueFilter(publicField) });
      return sharings.filter((sharing) => sharing[publicField] && !sharing[userIdField]).map(summarizeSharing);
    }),
  );
  return sharingsByType.flat();
};

// At startup, so that administrators can configure a public user before the switch is enabled by default
export const checkPublicSharingsWithoutUser = async (context: AuthContext): Promise<void> => {
  const collections = await findPublicSharingsWithoutUser(context);
  if (collections.length === 0) {
    return;
  }
  if (isDataSharingSecureByDefault()) {
    logApp.warn('[OPENCTI] Some public collections have no public user: they are refused until an administrator configures one (app:data_sharing:secure_by_default=true).', { collections });
    return;
  }
  logApp.warn('[OPENCTI] Some public collections have no public user: they are served with full access to the platform data (app:data_sharing:secure_by_default=false). '
    + 'They will be refused in an upcoming version: configure a public user on each, then set APP__DATA_SHARING__SECURE_BY_DEFAULT=true to opt in now.', { collections });
};

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
