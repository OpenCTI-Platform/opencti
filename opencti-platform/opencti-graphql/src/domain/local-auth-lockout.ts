// -- Local authentication lockout (soft lock) --
// After too many failed local password logins, the email is temporarily locked.
// The whole state lives in Redis: the account status is never changed, and open sessions and API tokens keep working.

import { isFeatureEnabled, LOCAL_AUTH_LOCKOUT_FEATURE_FLAG } from '../config/conf';
import { AuthenticationFailure } from '../config/errors';
import { getEntityFromCache } from '../database/cache';
import { type LocalAuthLockoutTimings, redisClearLocalAuthLockout, redisRecordLocalAuthAttempt } from '../database/redis';
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

const MINUTE_MS = 60 * 1000;

// The remaining minutes are sent in the error data, so that the login form can show them
const LocalAuthLocked = (remainingMs: number) => AuthenticationFailure(
  'Your account has been locked for security reasons. Please try again later.',
  { remaining_minutes: Math.ceil(remainingMs / MINUTE_MS) },
);

export const isLocalAuthLockedError = (error: unknown) => {
  const data = (error as { extensions?: { data?: { remaining_minutes?: number } } } | undefined)?.extensions?.data;
  return data?.remaining_minutes !== undefined;
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
    durationMs: (settings.local_auth_lockout_duration ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_duration) * MINUTE_MS,
    maxDurationMs: (settings.local_auth_lockout_max_duration ?? LOCAL_AUTH_LOCKOUT_DEFAULTS.local_auth_lockout_max_duration) * MINUTE_MS,
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
    // Counts the attempt as a failure before the password is checked, and throws the lock error during a lock.
    // Returns the error to throw if the password is wrong: the lock error when this attempt locked the account
    recordAttempt: async () => {
      const { allowed, remainingMs } = await redisRecordLocalAuthAttempt(emailHash, timings);
      if (!allowed) {
        throw LocalAuthLocked(remainingMs);
      }
      return remainingMs > 0 ? LocalAuthLocked(remainingMs) : AuthenticationFailure();
    },
    clear: () => redisClearLocalAuthLockout(emailHash),
  };
};

// Called once a login is fully accepted (local, Basic auth or another form provider): resets the lockout of the email
export const clearLocalAuthLockout = async (email: string) => {
  const lockout = await loadLocalAuthLockout(email);
  await lockout?.clear();
};
