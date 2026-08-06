import { isFeatureEnabled, MERGE_USERS_FEATURE_FLAG } from '../../config/conf';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreCommon } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { INTERNAL_USERS, isBypassUser } from '../../utils/access';
import { buildApiUserMergeCoverage, type UserMergeApiCoverage } from './userMerge-coverage';
import { executeUserMerge, readUserMergeJournal } from './userMerge-engine';
import { type UserMergeJournalEntry, type UserMergeOptions, type UserMergeResult, UserMergeRightsStrategy } from './userMerge-types';

/**
 * Options as they arrive from GraphQL: every field is optional there, because the schema
 * carries the defaults. They are re-applied here so that a caller that is not the GraphQL
 * layer cannot end up with an undefined dry-run flag.
 */
export interface UserMergeOptionsInput {
  dryRun?: boolean | null;
  rightsStrategy?: UserMergeRightsStrategy | null;
  acknowledgeExposureChange?: boolean | null;
}

/**
 * Defaults are the safe ones and are applied here rather than trusted from the caller:
 * a merge invoked with no options must be a dry-run, and must not widen rights.
 */
export const resolveUserMergeOptions = (options?: UserMergeOptionsInput | null): UserMergeOptions => {
  return {
    dryRun: options?.dryRun ?? true,
    rightsStrategy: options?.rightsStrategy ?? UserMergeRightsStrategy.Strict,
    acknowledgeExposureChange: options?.acknowledgeExposureChange ?? false,
  };
};

/**
 * Input guard-rails that need no database access, kept separate so they can be unit-tested
 * without a running platform.
 */
export const assertValidUserMergeIds = (sourceId: string, targetId: string): void => {
  if (!sourceId || !targetId) {
    throw FunctionalError('Source and target users are required to merge', { sourceId, targetId });
  }
  if (sourceId === targetId) {
    throw FunctionalError('Cannot merge a user into itself', { sourceId, targetId });
  }
  // Internal users (SYSTEM, RETENTION MANAGER, …) are platform machinery, not accounts.
  if (INTERNAL_USERS[sourceId] || INTERNAL_USERS[targetId]) {
    throw FunctionalError('Cannot merge an internal platform user', { sourceId, targetId });
  }
};

/**
 * Security boundary of the feature, enforced in the domain in addition to the schema
 * directives. The directives cover the GraphQL path; this covers any other caller.
 *
 * It throws. It never returns early on an unauthorized call — reporting a success-shaped
 * result to a caller that was refused is the behaviour this feature is specified against.
 */
export const assertUserMergeAllowed = (user: AuthUser): void => {
  if (!isFeatureEnabled(MERGE_USERS_FEATURE_FLAG)) {
    throw UnsupportedError('Feature is disabled', { flag: MERGE_USERS_FEATURE_FLAG });
  }
  if (!isBypassUser(user)) {
    throw ForbiddenAccess('Merging users requires the BYPASS capability', { user_id: user.id });
  }
};

const loadMergeableUser = async (context: AuthContext, user: AuthUser, userId: string, role: 'source' | 'target') => {
  const found = await storeLoadById<BasicStoreCommon>(context, user, userId, ENTITY_TYPE_USER);
  if (!found) {
    throw FunctionalError(`Unknown ${role} user`, { user_id: userId });
  }
  return found;
};

export const userMerge = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
  options?: UserMergeOptionsInput | null,
): Promise<UserMergeResult> => {
  assertUserMergeAllowed(user);
  assertValidUserMergeIds(sourceId, targetId);
  await loadMergeableUser(context, user, sourceId, 'source');
  await loadMergeableUser(context, user, targetId, 'target');
  const resolvedOptions = resolveUserMergeOptions(options);
  return executeUserMerge(context, sourceId, targetId, resolvedOptions);
};

/**
 * Read on its own, without launching anything: an operator has to be able to check what the
 * build in front of them actually covers before deciding to run a merge at all.
 */
export const userMergeCoverage = async (
  _context: AuthContext,
  user: AuthUser,
  disposition?: string | null,
): Promise<UserMergeApiCoverage> => {
  assertUserMergeAllowed(user);
  return buildApiUserMergeCoverage(undefined, disposition);
};

// Bounds enforced here so that a future, real journal implementation cannot be abused
// into a heavy read regardless of what a caller (GraphQL or otherwise) requests.
const USER_MERGE_JOURNAL_DEFAULT_FIRST = 20;
const USER_MERGE_JOURNAL_MIN_FIRST = 1;
const USER_MERGE_JOURNAL_MAX_FIRST = 200;

export const resolveUserMergeJournalFirst = (first?: number | null): number => {
  if (first === undefined || first === null) {
    return USER_MERGE_JOURNAL_DEFAULT_FIRST;
  }
  return Math.min(Math.max(first, USER_MERGE_JOURNAL_MIN_FIRST), USER_MERGE_JOURNAL_MAX_FIRST);
};

export const userMergeJournal = async (
  _context: AuthContext,
  user: AuthUser,
  mergeId?: string | null,
  first?: number | null,
): Promise<UserMergeJournalEntry[]> => {
  assertUserMergeAllowed(user);
  return readUserMergeJournal(mergeId ?? undefined, resolveUserMergeJournalFirst(first));
};
