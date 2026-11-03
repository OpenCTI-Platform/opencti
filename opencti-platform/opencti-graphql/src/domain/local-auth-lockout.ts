// -- Local authentication lockout --
// Each failed local password login or MFA code locks the email temporarily, with a duration doubled on each failure.
// Once the max attempts are reached, the final action applies: a lock for the whole window, or the account set to Locked.
// The temporary locks live in Redis only: the account status is not changed, and open sessions and API tokens keep working.

import { ACCOUNT_STATUSES, isFeatureEnabled, LOCAL_AUTH_LOCKOUT_FEATURE_FLAG } from '../config/conf';
import { AuthenticationFailure } from '../config/errors';
import { getEntityFromCache } from '../database/cache';
import { type LocalAuthLockoutTimings, type LocalAuthLockType, redisClearLocalAuthLockout, redisRecordLocalAuthAttempt, redisReleaseLocalAuthAttempt } from '../database/redis';
import { LocalAuthLockoutFinalAction } from '../generated/graphql';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/settings';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { normalizeEmail } from '../utils/email';
import { hashSHA256 } from '../utils/hash';

// Values returned for the local authentication lockout policy when the settings hold none.
// Thresholds and window follow NIST SP 800-53 AC-7: 3 attempts for administrative accounts, 10 for the other users, within 15 minutes
export const LOCAL_AUTH_LOCKOUT_DEFAULTS = {
  // Existing platforms keep the lockout disabled, new platforms start with it enabled (data initialization)
  local_auth_lockout_enabled: false,
  local_auth_lockout_max_attempts: 10,
  local_auth_lockout_admin_max_attempts: 3,
  // Applied once max attempts are reached: a lock for the whole window, or the account set to Locked until an admin unlocks it
  local_auth_lockout_final_action: LocalAuthLockoutFinalAction.Temporary,
  local_auth_lockout_window: 15, // minutes
  local_auth_lockout_duration: 30, // seconds
  local_auth_lockout_max_duration: 10800, // seconds, 3h
};
export type LocalAuthLockoutKey = keyof typeof LOCAL_AUTH_LOCKOUT_DEFAULTS;
export const LOCAL_AUTH_LOCKOUT_KEYS = Object.keys(LOCAL_AUTH_LOCKOUT_DEFAULTS) as LocalAuthLockoutKey[];

const SECOND_MS = 1000;
const MINUTE_MS = 60 * SECOND_MS;

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

const getLockoutTimings = async (): Promise<LocalAuthLockoutTimings | undefined> => {
  if (!isFeatureEnabled(LOCAL_AUTH_LOCKOUT_FEATURE_FLAG)) {
    return undefined;
  }
  const context = executionContext('local_auth_lockout');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  if (!(settings.local_auth_lockout_enabled ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_enabled)) {
    return undefined;
  }
  return {
    maxAttempts: settings.local_auth_lockout_max_attempts ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_max_attempts,
    windowMs: (settings.local_auth_lockout_window ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_window) * MINUTE_MS,
    durationMs: (settings.local_auth_lockout_duration ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_duration) * SECOND_MS,
    maxDurationMs: (settings.local_auth_lockout_max_duration ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_max_duration) * SECOND_MS,
    finalAction: settings.local_auth_lockout_final_action ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_final_action,
  };
};

// Returns undefined when the lockout is disabled, so that the login keeps its previous behavior
export const loadLocalAuthLockout = async (email: string) => {
  const timings = await getLockoutTimings();
  if (!timings) {
    return undefined;
  }
  // Unknown emails are counted too, so that a lock never reveals whether an account exists
  const emailHash = hashSHA256(normalizeEmail(email));
  return {
    // Counts the attempt as a failure and locks the email before the password or the MFA code is checked,
    // and throws the lock error during a lock. Returns what to do if the check fails:
    // the lock error to throw, and whether the account must be set to Locked (permanent final action)
    recordAttempt: async () => {
      const { allowed, remainingMs, lockType, isFinal } = await redisRecordLocalAuthAttempt(emailHash, timings);
      if (!allowed) {
        throw LocalAuthLocked(lockType, remainingMs);
      }
      return { failure: LocalAuthLocked(lockType, remainingMs), locksAccount: isFinal && lockType === 'permanent' };
    },
    // A right password that still waits for its MFA code: lifts the lock of this attempt but keeps the counter
    release: () => redisReleaseLocalAuthAttempt(emailHash),
    clear: () => redisClearLocalAuthLockout(emailHash),
  };
};

// Called once a login is fully accepted (local, Basic auth, another provider or a valid MFA code): resets the lockout of the email
export const clearLocalAuthLockout = async (email: string) => {
  const lockout = await loadLocalAuthLockout(email);
  await lockout?.clear();
};

// Called when a right password still waits for its MFA code, so that only a valid MFA code resets the counter
export const releaseLocalAuthAttempt = async (email: string) => {
  const lockout = await loadLocalAuthLockout(email);
  await lockout?.release();
};
