// -- Local authentication lockout (soft lock) --
// After too many failed local password logins, the email is temporarily locked.
// The whole state lives in Redis: the account status is never changed, and open sessions and API tokens keep working.

import { isFeatureEnabled, LOCAL_AUTH_LOCKOUT_FEATURE_FLAG } from '../config/conf';
import { AuthenticationFailure } from '../config/errors';
import { getEntityFromCache } from '../database/cache';
import { type LocalAuthLockoutTimings, redisClearLocalAuthLockout, redisRecordLocalAuthAttempt } from '../database/redis';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/settings';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { normalizeEmail } from '../utils/email';
import { hashSHA256 } from '../utils/hash';

// Values returned for the local authentication lockout policy when the settings hold none
export const LOCAL_AUTH_LOCKOUT_DEFAULTS = {
  local_auth_lockout_enabled: false,
  local_auth_lockout_max_attempts: 5,
  local_auth_lockout_window: 1440, // minutes, 24h
  local_auth_lockout_duration: 15, // minutes
  local_auth_lockout_max_duration: 180, // minutes, 3h
};
export type LocalAuthLockoutKey = keyof typeof LOCAL_AUTH_LOCKOUT_DEFAULTS;
export const LOCAL_AUTH_LOCKOUT_KEYS = Object.keys(LOCAL_AUTH_LOCKOUT_DEFAULTS) as LocalAuthLockoutKey[];

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
