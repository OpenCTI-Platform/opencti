import { ENABLED_DEMO_MODE, isFeatureEnabled, logApp, MERGE_USERS_FEATURE_FLAG } from '../../config/conf';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { storeLoadById } from '../../database/middleware-loader';
import { publishUserAction } from '../../listener/UserActionListener';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreCommon } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { INTERNAL_USERS, isBypassUser, REDACTED_USER } from '../../utils/access';
import { buildApiUserMergeCoverage, type UserMergeApiCoverage } from './userMerge-coverage';
import { executeUserMerge, readUserMergeJournal } from './userMerge-engine';
import { computeUserMergeSourceDeletionReadiness, deleteUserMergeSource, type UserMergeSourceDeletionReadiness } from './userMerge-sourceDeletion';
import { type UserMergeJournalEntry, type UserMergeOptions, type UserMergeResult, UserMergeRightsStrategy, UserMergeStatus } from './userMerge-types';

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

type MergeableUser = BasicStoreCommon & { user_email?: string };

const loadMergeableUser = async (context: AuthContext, user: AuthUser, userId: string, role: 'source' | 'target') => {
  const found = await storeLoadById<MergeableUser>(context, user, userId, ENTITY_TYPE_USER);
  if (!found) {
    throw FunctionalError(`Unknown ${role} user`, { user_id: userId });
  }
  return found;
};

/**
 * The merge trace asked for by the product: "user xxxx has been merged into user xxxx".
 *
 * Published here and not from the engine, which deliberately takes no calling user: the trace
 * has to name the administrator who ran the merge, and the activity listener only retains
 * actions whose origin is a real request — one published as SYSTEM_USER would be dropped.
 *
 * It is a readability aid, not evidence. Activity events are Enterprise Edition only and can
 * be purged by a retention rule, which is acceptable precisely because nothing irreversible
 * reads them: the deletion gate re-runs a dry-run instead of trusting a past attestation.
 *
 * The source carries the context id: the question asked later is why that account is disabled.
 *
 * Failing to publish does not fail the merge. The trace runs once every handler has written, and
 * `publishUserAction` awaits its listeners: letting a listener reject here — the codebase default
 * — would answer a GraphQL error for an applied merge and drop the id the operator needs to read
 * the journal. Nothing else in the platform is asked to swallow this, but nothing else publishes
 * after a write this hard to read back.
 */
const publishMergeTrace = async (user: AuthUser, source: MergeableUser, target: MergeableUser, result: UserMergeResult) => {
  const sourceEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : source.user_email;
  const targetEmail = ENABLED_DEMO_MODE ? REDACTED_USER.user_email : target.user_email;
  try {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `merges user \`${sourceEmail}\` into user \`${targetEmail}\``,
      context_data: {
        id: source.internal_id,
        entity_type: ENTITY_TYPE_USER,
        input: {
          merge_id: result.id,
          source_id: result.source_id,
          target_id: result.target_id,
          rights_strategy: result.rights_strategy,
        },
      },
    });
  } catch (err) {
    logApp.error('[MERGE_USERS] merge trace not published', { merge_id: result.id, cause: err instanceof Error ? err.message : String(err) });
  }
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
  const source = await loadMergeableUser(context, user, sourceId, 'source');
  const target = await loadMergeableUser(context, user, targetId, 'target');
  const resolvedOptions = resolveUserMergeOptions(options);
  const result = await executeUserMerge(context, sourceId, targetId, resolvedOptions);
  if (!resolvedOptions.dryRun && result.status === UserMergeStatus.Success) {
    await publishMergeTrace(user, source, target, result);
  }
  return result;
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

/**
 * Whether the source may now be deleted. Exposed as a read: the operator has to be able to check
 * the answer before scheduling the operation at all.
 *
 * "Read" describes what it returns, not what it costs: the verdict comes from a full dry-run on
 * the pair, which the engine journals handler by handler like any other pass. Trusting a stored
 * attestation instead would answer from the state of a past run, and the whole point of the gate
 * is that it answers from the state of now.
 */
export const userMergeSourceDeletionReadiness = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
): Promise<UserMergeSourceDeletionReadiness> => {
  assertUserMergeAllowed(user);
  assertValidUserMergeIds(sourceId, targetId);
  await loadMergeableUser(context, user, sourceId, 'source');
  await loadMergeableUser(context, user, targetId, 'target');
  return computeUserMergeSourceDeletionReadiness(context, sourceId, targetId);
};

/**
 * Deletes the source once the gate opens. A mutation rather than a step of the merge: the
 * operator decides when, and re-checking readiness here rather than trusting a readiness read
 * earlier means the answer cannot have gone stale between the two calls.
 */
export const userMergeDeleteSource = async (
  context: AuthContext,
  user: AuthUser,
  sourceId: string,
  targetId: string,
): Promise<string> => {
  assertUserMergeAllowed(user);
  assertValidUserMergeIds(sourceId, targetId);
  await loadMergeableUser(context, user, sourceId, 'source');
  await loadMergeableUser(context, user, targetId, 'target');
  return deleteUserMergeSource(context, user, sourceId, targetId);
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
