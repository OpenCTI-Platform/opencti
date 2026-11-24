// -- Local authentication lockout: the default policy --
// Kept apart from the lockout itself, so that the settings and the lock email read the policy without importing the lockout

import { LocalAuthLockoutFinalAction } from '../generated/graphql';

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
