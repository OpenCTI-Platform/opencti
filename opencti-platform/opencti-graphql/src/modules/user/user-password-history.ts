import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { isFeatureEnabled, logApp, PASSWORD_HISTORY_FEATURE_FLAG } from '../../config/conf';
import { PASSWORD_REUSED, PasswordChangeThrottled, PasswordReused } from '../../config/errors';
import { elRawCount, elRawUpdateByQuery } from '../../database/engine';
import { publishCacheResetEvent, redisConsumePasswordChangeAttempt } from '../../database/redis';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { publishUserAction } from '../../listener/UserActionListener';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { type BasicStoreEntityUser, ENTITY_TYPE_USER } from './user-types';

// Password history: a new local password must differ from the current one and the N - 1 before it.
// Only one-way bcrypt hashes are kept, never a clear text password.

export const PASSWORD_HISTORY_MAX_COUNT = 24;

type PasswordHashes = Pick<BasicStoreEntityUser, 'password' | 'password_history'>;
type PasswordChangeFlow = 'self' | 'admin' | 'reset';

const BCRYPT_HASH_PATTERN = /^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/;
const BULK_UPDATE_ATTEMPTS = 5;

export const isValidPasswordHistoryCount = (value: unknown): value is number => {
  return Number.isInteger(value) && (value as number) >= 0 && (value as number) <= PASSWORD_HISTORY_MAX_COUNT;
};

// The only reader of the setting: 0 when the feature flag is off or the stored value is not usable.
export const readPasswordHistoryCount = (settings: Pick<BasicStoreSettings, 'password_policy_history_count'> | null | undefined): number => {
  if (!isFeatureEnabled(PASSWORD_HISTORY_FEATURE_FLAG)) {
    return 0;
  }
  const value = settings?.password_policy_history_count;
  if (value === undefined || value === null) {
    return 0;
  }
  if (!isValidPasswordHistoryCount(value)) {
    logApp.warn('[PASSWORD_HISTORY] Ignoring an invalid password history count', { value });
    return 0;
  }
  return value;
};

// External (SSO) users and service accounts have no password of their own to check or remember
export const isLocalUser = (user: Pick<BasicStoreEntityUser, 'external' | 'user_service_account'>) => {
  return !user.external && !user.user_service_account;
};

const isBcryptHash = (value: unknown): value is string => typeof value === 'string' && BCRYPT_HASH_PATTERN.test(value);

// The current hash first, then the stored ones newest first; anything that is not a bcrypt hash is dropped.
const knownPasswordHashes = (user: PasswordHashes): string[] => {
  const history = Array.isArray(user.password_history) ? user.password_history : [];
  return [user.password, ...history].filter(isBcryptHash);
};

// The history to store when a new password replaces the current one: the current hash and the newest
// stored ones, N - 1 at most, since the new password is the Nth. An empty list removes the field.
export const computeNextPasswordHistory = (user: PasswordHashes, n: number): string[] => {
  if (n <= 1) {
    return [];
  }
  return knownPasswordHashes(user).slice(0, n - 1);
};

let paddingHash: string | undefined;
const getPaddingHash = () => {
  if (!paddingHash) {
    paddingHash = bcrypt.hashSync(uuid());
  }
  return paddingHash;
};

// Always compares N hashes, padding the window when the user has fewer, so that the time taken
// never tells which old password matched or how many changes the user made.
export const isPasswordReused = async (user: PasswordHashes, clearPassword: string, n: number): Promise<boolean> => {
  if (n <= 0) {
    return false;
  }
  const window = knownPasswordHashes(user).slice(0, n);
  while (window.length < n) {
    window.push(getPaddingHash());
  }
  const matches = await Promise.all(window.map((hash) => bcrypt.compare(clearPassword, hash)));
  return matches.some((match) => match);
};

export const consumePasswordChangeAttempt = async (userId: string) => {
  const allowed = await redisConsumePasswordChangeAttempt(userId);
  if (!allowed) {
    throw PasswordChangeThrottled();
  }
};

const passwordChangeFlow = (user: AuthUser, targetUserId: string): PasswordChangeFlow => {
  if (user.id === SYSTEM_USER.id) {
    return 'reset';
  }
  return user.id === targetUserId ? 'self' : 'admin';
};

export const checkPasswordNotReused = async (
  _context: AuthContext,
  user: AuthUser,
  userToUpdate: PasswordHashes & Pick<BasicStoreEntityUser, 'id'>,
  clearPassword: string,
  n: number,
) => {
  const reused = await isPasswordReused(userToUpdate, clearPassword, n);
  if (!reused) {
    return;
  }
  const flow = passwordChangeFlow(user, userToUpdate.id);
  // Built by hand: the request variables, which hold the clear text password, never go in
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'unauthorized',
    event_access: 'administration',
    status: 'error',
    context_data: {
      operation: 'password_reuse',
      input: { user_id: userToUpdate.id, reason: PASSWORD_REUSED, flow },
    },
  });
  // The audit log needs an Enterprise Edition licence: this line is the trace on every platform
  logApp.warn('[PASSWORD_HISTORY] Password reuse refused', { target_user_id: userToUpdate.id, submitter_id: user.id, flow });
  throw PasswordReused();
};

const usersWithPasswordHistoryQuery = {
  bool: {
    must: [{ term: { 'entity_type.keyword': ENTITY_TYPE_USER } }],
    filter: [{ exists: { field: 'password_history' } }],
  },
};

// Unlike the password validity updates, external users are included: a local user who switched to SSO keeps no history either.
const updateAllUsersPasswordHistory = async (script: { source: string; params?: Record<string, unknown> }) => {
  for (let attempt = 1; attempt <= BULK_UPDATE_ATTEMPTS; attempt += 1) {
    const result = await elRawUpdateByQuery({
      index: [READ_INDEX_INTERNAL_OBJECTS],
      refresh: true,
      conflicts: 'proceed',
      body: { script, query: usersWithPasswordHistoryQuery },
    });
    if (!result?.version_conflicts) {
      break;
    }
  }
  await publishCacheResetEvent(ENTITY_TYPE_USER);
};

export const clearAllUsersPasswordHistory = async () => {
  await updateAllUsersPasswordHistory({ source: "ctx._source.remove('password_history');" });
  const remaining = await elRawCount({ index: READ_INDEX_INTERNAL_OBJECTS, body: { query: usersWithPasswordHistoryQuery } });
  if (remaining > 0) {
    logApp.warn('[PASSWORD_HISTORY] Some users still hold a password history after the clean-up', { remaining });
  }
};

// Keeps the N - 1 newest hashes of every user that holds more
export const trimAllUsersPasswordHistory = async (n: number) => {
  if (n <= 1) {
    await clearAllUsersPasswordHistory();
    return;
  }
  await updateAllUsersPasswordHistory({
    source: `
      if (ctx._source.password_history.size() > params.keep) {
        ctx._source.password_history = new ArrayList(ctx._source.password_history.subList(0, params.keep));
      } else {
        ctx.op = 'noop';
      }
    `,
    params: { keep: n - 1 },
  });
};

// Run at startup: with the feature flag off, the stored value is reset and every history deleted,
// so turning the flag back on later always starts from scratch.
export const cleanUpPasswordHistoryWhenDisabled = async (
  settings: Pick<BasicStoreSettings, 'password_policy_history_count'>,
  resetStoredCount: () => Promise<unknown>,
) => {
  if (isFeatureEnabled(PASSWORD_HISTORY_FEATURE_FLAG)) {
    return;
  }
  const storedCount = settings.password_policy_history_count ?? 0;
  const usersWithHistory = await elRawCount({ index: READ_INDEX_INTERNAL_OBJECTS, body: { query: usersWithPasswordHistoryQuery } });
  if (storedCount === 0 && usersWithHistory === 0) {
    return;
  }
  logApp.info('[PASSWORD_HISTORY] Feature disabled, removing stored password history', { storedCount, usersWithHistory });
  if (storedCount !== 0) {
    await resetStoredCount();
  }
  if (usersWithHistory > 0) {
    await clearAllUsersPasswordHistory();
  }
};
