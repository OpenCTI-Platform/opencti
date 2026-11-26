import { booleanConf, logApp } from '../../config/conf';
import { ForbiddenAccess } from '../../config/errors';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthUser } from '../../types/user';

const SECURE_BY_DEFAULT_KEY = 'app:authentication:secure_by_default';
// The warning that names an account still using Basic auth with two-factor authentication is logged at most once per hour
const TWO_FACTOR_WARNING_INTERVAL_MS = 60 * 60 * 1000;

type TwoFactorSettings = Pick<BasicStoreSettings, 'otp_mandatory'>;
type TwoFactorAccount = Pick<AuthUser, 'otp_activated'>;

// API Basic authentication sends the local password with every request (NIST SP 800-53 IA-2).
// Absent on the platforms created before the setting existed: they keep it enabled.
export const isApiBasicAuthEnabled = (settings: Pick<BasicStoreSettings, 'api_basic_auth_enabled'>) => {
  return settings.api_basic_auth_enabled !== false;
};

// Secure by default switch of the authentication: on, Basic auth is refused to the accounts that two-factor authentication applies to.
// Read at call time so that the tests can set it with conf.set
export const isAuthenticationSecureByDefault = () => {
  return booleanConf(SECURE_BY_DEFAULT_KEY, false);
};

// Checked before the password, for every account: BYPASS and the built-in admin included.
// A refused request is not a login attempt, so the local authentication lockout does not count it.
export const checkApiBasicAuthAllowed = (settings: Pick<BasicStoreSettings, 'api_basic_auth_enabled'>) => {
  if (!isApiBasicAuthEnabled(settings)) {
    throw ForbiddenAccess('API Basic authentication is disabled on this platform, use an API token');
  }
};

// Two-factor authentication applies to every account of a platform that enforces it, and to the accounts that enabled it
const isTwoFactorApplied = (settings: TwoFactorSettings, account: TwoFactorAccount | undefined) => {
  return !!settings.otp_mandatory || !!account?.otp_activated;
};

// Checked before the password, after checkApiBasicAuthAllowed and with the same effects: the password of an account
// with two-factor authentication is never checked through Basic auth, and its attempts are never counted.
// The account is only loaded when needed: with the switch on, and when two-factor authentication is not mandatory
export const checkApiBasicAuthTwoFactor = async (settings: TwoFactorSettings, loadAccount: () => Promise<TwoFactorAccount | undefined>) => {
  if (!isAuthenticationSecureByDefault()) {
    return;
  }
  if (isTwoFactorApplied(settings, settings.otp_mandatory ? undefined : await loadAccount())) {
    throw ForbiddenAccess('Two-factor authentication applies to this account: API Basic authentication cannot ask for it, use an API token');
  }
};

const twoFactorWarnings = new Map<string, number>();

// After a successful login, while the switch is off: names the accounts whose integrations must move to an API token
export const warnApiBasicAuthTwoFactor = (user: Pick<AuthUser, 'id' | 'otp_activated'>, settings: TwoFactorSettings) => {
  if (isAuthenticationSecureByDefault() || !isTwoFactorApplied(settings, user)) {
    return;
  }
  const now = Date.now();
  const lastWarning = twoFactorWarnings.get(user.id);
  if (lastWarning !== undefined && now - lastWarning < TWO_FACTOR_WARNING_INTERVAL_MS) {
    return;
  }
  twoFactorWarnings.set(user.id, now);
  // The user id only, never the credentials
  logApp.warn(`[OPENCTI] API Basic authentication used by an account with two-factor authentication (${SECURE_BY_DEFAULT_KEY}=false). `
    + 'It will be refused in an upcoming version: this integration must use an API token.', { user_id: user.id });
};
