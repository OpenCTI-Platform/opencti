// -- Local authentication lockout --
// Each failed local password login or MFA code is counted within the window, without any lock.
// Once the max attempts are reached, the final action applies: a lock for the lockout duration, or the account set to Locked.
// The temporary lock lives in Redis only: the account status is not changed, and open sessions and API tokens keep working.
// The permanent lock lasts until an administrator sets the account back to Active, or until a login with another provider.

import { v4 as uuid } from 'uuid';
import { ACCOUNT_STATUSES, ENABLED_DEMO_MODE, isFeatureEnabled, LOCAL_AUTH_LOCKOUT_FEATURE_FLAG } from '../config/conf';
import { AuthenticationFailure } from '../config/errors';
import { getEntitiesMapFromCache, getEntityFromCache } from '../database/cache';
import { type LocalAuthLockoutTimings, type LocalAuthLockType, redisClearLocalAuthLockout, redisRecordLocalAuthAttempt, redisReleaseLocalAuthAttempt } from '../database/redis';
import { LocalAuthLockoutFinalAction } from '../generated/graphql';
import { publishUserAction, type UserLockSource } from '../listener/UserActionListener';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { ENTITY_TYPE_USER } from '../modules/user/user-types';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { BYPASS, executionContext, REDACTED_USER, SETTINGS_SETACCESSES, SETTINGS_SETAUTH, SETTINGS_SETPARAMETERS, SYSTEM_USER } from '../utils/access';
import { normalizeEmail } from '../utils/email';
import { hashSHA256 } from '../utils/hash';

// Values returned for the local authentication lockout policy when the settings hold none.
// Thresholds and window follow NIST SP 800-53 AC-7: 3 attempts for administrative accounts, 10 for the other users, within 15 minutes
export const LOCAL_AUTH_LOCKOUT_DEFAULTS = {
  // Existing platforms keep the lockout disabled, new platforms start with it enabled (data initialization)
  local_auth_lockout_enabled: false,
  local_auth_lockout_max_attempts: 10,
  local_auth_lockout_admin_max_attempts: 3,
  // Applied once max attempts are reached: a lock for the lockout duration, or the account set to Locked until an admin unlocks it
  local_auth_lockout_final_action: LocalAuthLockoutFinalAction.Temporary,
  // Failed attempts older than the window are forgotten. 0 removes the time limit: failed attempts are kept until
  // a successful login or the end of a temporary lock
  local_auth_lockout_window: 15, // minutes
  // Duration of the lock applied by the temporary final action
  local_auth_lockout_duration: 15, // minutes
};
export type LocalAuthLockoutKey = keyof typeof LOCAL_AUTH_LOCKOUT_DEFAULTS;
export const LOCAL_AUTH_LOCKOUT_KEYS = Object.keys(LOCAL_AUTH_LOCKOUT_DEFAULTS) as LocalAuthLockoutKey[];

const SECOND_MS = 1000;
const MINUTE_MS = 60 * SECOND_MS;
// The failures and the permanent lock of a real account are kept until a successful login or an administrator.
// Those of an unknown email are still forgotten after a day, so that random emails cannot fill Redis
const UNKNOWN_EMAIL_RETENTION_MS = 24 * 60 * MINUTE_MS;

// The lock type and the remaining time are sent in the error data, so that the login form can show them.
// A permanent lock has no remaining time: an administrator must unlock the account
const LocalAuthLocked = (lockType: LocalAuthLockType, remainingMs: number) => {
  if (lockType === 'permanent') {
    return AuthenticationFailure(ACCOUNT_STATUSES.Locked, { lock: lockType });
  }
  return AuthenticationFailure('Your account has been locked for security reasons. Please try again later.', {
    lock: lockType,
    remaining_seconds: Math.ceil(remainingMs / SECOND_MS),
    remaining_minutes: Math.ceil(remainingMs / MINUTE_MS),
  });
};

export const isLocalAuthLockedError = (error: unknown) => {
  const data = (error as { extensions?: { data?: { lock?: LocalAuthLockType } } } | undefined)?.extensions?.data;
  return data?.lock !== undefined;
};

// An administrative account holds a capability that gives control over the platform, as validated by Security:
// BYPASS, the users, groups and roles (any right can be granted to oneself), the authentication (including this lockout)
// and the platform parameters. The other SETTINGS capabilities (labels, vocabularies...) and the access to the
// administration alone (SETTINGS) keep the users threshold
const ADMINISTRATIVE_CAPABILITIES = [BYPASS, SETTINGS_SETACCESSES, SETTINGS_SETAUTH, SETTINGS_SETPARAMETERS];
export const isAdministrativeAccount = (user: Pick<AuthUser, 'capabilities'>) => {
  return (user.capabilities ?? []).some(({ name }) => ADMINISTRATIVE_CAPABILITIES.includes(name));
};

const loadPlatformUser = async (context: AuthContext, userId?: string) => {
  if (!userId) {
    return undefined;
  }
  const platformUsers = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return platformUsers.get(userId);
};

// Returns the policy of the email, and its user (undefined for an unknown email), only when the lockout is enabled
const getLockoutPolicy = async (userId?: string): Promise<{ timings: LocalAuthLockoutTimings; user?: AuthUser } | undefined> => {
  if (!isFeatureEnabled(LOCAL_AUTH_LOCKOUT_FEATURE_FLAG)) {
    return undefined;
  }
  const context = executionContext('local_auth_lockout');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  if (!(settings.local_auth_lockout_enabled ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_enabled)) {
    return undefined;
  }
  // NIST SP 800-53 AC-7: administrative accounts get a lower threshold than the other users.
  // Unknown emails get the users threshold, so that a lock never reveals whether an account exists
  const user = await loadPlatformUser(context, userId);
  const isAdministrative = !!user && isAdministrativeAccount(user);
  const maxAttempts = isAdministrative
    ? settings.local_auth_lockout_admin_max_attempts ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_admin_max_attempts
    : settings.local_auth_lockout_max_attempts ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_max_attempts;
  const windowMs = (settings.local_auth_lockout_window ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_window) * MINUTE_MS;
  const finalAction = settings.local_auth_lockout_final_action ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_final_action;
  const durationMs = (settings.local_auth_lockout_duration ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_duration) * MINUTE_MS;
  // The permanent lock never expires for an existing account (0), including the service accounts and the external users
  // that are never set to Locked: otherwise each expiry would give new attempts
  const permanentLockMs = userId ? 0 : UNKNOWN_EMAIL_RETENTION_MS;
  const timings = {
    maxAttempts,
    windowMs: windowMs === 0 && !userId ? UNKNOWN_EMAIL_RETENTION_MS : windowMs,
    finalLockMs: finalAction === LocalAuthLockoutFinalAction.Permanent ? permanentLockMs : durationMs,
    finalAction,
  };
  return { timings, user };
};

// Where the failed attempt comes from, and its source IP, for the activity event of a lock
export type LocalAuthAttemptOrigin = { source: UserLockSource; ip?: string };

// One activity event per lock, for an existing account only: an unknown email has no user to attribute it to.
// The event is attributed to the locked user, from the source IP of the attempt that locked it
const publishLocalAuthLock = async (user: AuthUser, timings: LocalAuthLockoutTimings, { source, ip }: LocalAuthAttemptOrigin) => {
  const origin = {
    socket: 'query',
    ip,
    user_id: user.id,
    group_ids: user.groups?.map((g) => g.internal_id) ?? [],
    organization_ids: user.organizations?.map((o) => o.internal_id) ?? [],
  };
  const isPermanent = timings.finalAction === LocalAuthLockoutFinalAction.Permanent;
  await publishUserAction({
    user: { ...user, origin },
    event_type: 'authentication',
    event_scope: 'lock',
    event_access: 'administration',
    status: 'error',
    context_data: {
      username: ENABLED_DEMO_MODE ? REDACTED_USER.name : user.user_email,
      lock_type: isPermanent ? 'permanent' : 'temporary',
      ...(!isPermanent && { lock_duration: timings.finalLockMs / MINUTE_MS }),
      max_attempts: timings.maxAttempts,
      source,
    },
  });
};

// Returns undefined when the lockout is disabled, so that the login keeps its previous behavior.
// The built-in admin (app:admin) is a break-glass account, never locked out: if every administrator gets locked,
// it is enabled again in the configuration to unlock them. Once other administrators exist, it should be disabled
// with APP__ADMIN__EXTERNALLY_MANAGED=true (its account is then set to Locked): the lockout settings form says so
export const loadLocalAuthLockout = async (email: string, userId?: string) => {
  if (userId === OPENCTI_ADMIN_UUID) {
    return undefined;
  }
  const policy = await getLockoutPolicy(userId);
  if (!policy) {
    return undefined;
  }
  const { timings, user } = policy;
  // Unknown emails are counted too, so that a lock never reveals whether an account exists
  const emailHash = hashSHA256(normalizeEmail(email));
  return {
    // Counts the attempt as a failure before the password or the MFA code is checked, and throws the lock error during a lock.
    // Returns what to do if the check fails: whether the account must be set to Locked (permanent final action),
    // and reject, which returns the error to throw: the lock error once the max attempts are reached
    // (below, the usual authentication failure). The attempt that reaches them publishes the lock in the activity.
    // If the check succeeds, release undoes this attempt only: its failure in its own window, and its lock,
    // but never the failures of a later window nor the lock of a concurrent failure
    recordAttempt: async () => {
      const attemptToken = uuid();
      const { allowed, remainingMs, lockType, isFinal, windowId } = await redisRecordLocalAuthAttempt(emailHash, timings, attemptToken);
      if (!allowed) {
        throw LocalAuthLocked(lockType, remainingMs);
      }
      return {
        locksAccount: isFinal && lockType === 'permanent',
        reject: async (origin: LocalAuthAttemptOrigin) => {
          if (!isFinal) {
            return AuthenticationFailure();
          }
          if (user) {
            await publishLocalAuthLock(user, timings, origin);
          }
          return LocalAuthLocked(lockType, remainingMs);
        },
        release: () => redisReleaseLocalAuthAttempt(emailHash, { attemptToken, windowId }),
      };
    },
  };
};

// Called once a login is fully accepted (local, Basic auth, another provider or a valid MFA code): resets the lockout of the email.
// Also when the lockout or its feature flag is disabled, so that enabling it again never brings back an old lock
export const clearLocalAuthLockout = async (email: string) => {
  await redisClearLocalAuthLockout(hashSHA256(normalizeEmail(email)));
};
