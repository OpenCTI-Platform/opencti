import { ForbiddenAccess } from '../../config/errors';
import type { BasicStoreSettings } from '../../types/settings';
import { isLocalAuthForcedEnabledFromEnv } from '../authenticationProvider/providers-configuration';

// API Basic authentication sends the local password with every request (NIST SP 800-53 IA-2).
// Absent on the platforms created before the setting existed: they keep it enabled.
export const isApiBasicAuthEnabled = (settings: Pick<BasicStoreSettings, 'api_basic_auth_enabled'>) => {
  return settings.api_basic_auth_enabled !== false;
};

// Checked before the password, for every account: BYPASS and the built-in admin included.
// A refused request is not a login attempt, so the local authentication lockout does not count it.
// #19531 (MFA on Basic auth) will plug in here.
export const checkApiBasicAuthAllowed = (settings: Pick<BasicStoreSettings, 'api_basic_auth_enabled' | 'local_auth'>) => {
  if (!isApiBasicAuthEnabled(settings)) {
    throw ForbiddenAccess('API Basic authentication is disabled on this platform, use an API token');
  }
  // Basic auth checks a local password: without the local authentication, there is none to check
  const isLocalAuthEnabled = isLocalAuthForcedEnabledFromEnv() || !!settings.local_auth?.enabled;
  if (!isLocalAuthEnabled) {
    throw ForbiddenAccess('Local authentication is disabled on this platform, use an API token');
  }
};
