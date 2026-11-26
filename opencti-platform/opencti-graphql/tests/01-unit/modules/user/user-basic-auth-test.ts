import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import conf, { logApp } from '../../../../src/config/conf';
import * as Cache from '../../../../src/database/cache';
import * as Engine from '../../../../src/database/engine';
import {
  checkApiBasicAuthAllowed,
  checkApiBasicAuthTwoFactor,
  isApiBasicAuthEnabled,
  isAuthenticationSecureByDefault,
  warnApiBasicAuthTwoFactor,
} from '../../../../src/modules/user/user-basic-auth';
import { authenticateUserByBasicAuth } from '../../../../src/modules/user/user-domain';
import { BYPASS, SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';
import type { BasicStoreSettings } from '../../../../src/types/settings';

vi.mock('../../../../src/database/cache');
vi.mock('../../../../src/database/redis'); // to prevent connection attempts
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elLoadBy: vi.fn(),
}));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

type BasicAuthSettings = Pick<BasicStoreSettings, 'api_basic_auth_enabled' | 'otp_mandatory'>;

const USE_API_TOKEN = /use an API token/;
const SWITCH = 'app:authentication:secure_by_default';
const HOUR_MS = 60 * 60 * 1000;

describe('API Basic authentication setting', () => {
  it('should refuse Basic auth when the setting is disabled', () => {
    expect(() => checkApiBasicAuthAllowed({ api_basic_auth_enabled: false })).toThrow(USE_API_TOKEN);
  });

  it('should accept Basic auth when the setting is enabled', () => {
    expect(() => checkApiBasicAuthAllowed({ api_basic_auth_enabled: true })).not.toThrow();
  });

  it('should read a missing setting as enabled, as on the platforms created before it', () => {
    const settings: BasicAuthSettings = {};
    expect(isApiBasicAuthEnabled(settings)).toBe(true);
    expect(() => checkApiBasicAuthAllowed(settings)).not.toThrow();
  });
});

describe('app:authentication:secure_by_default', () => {
  afterEach(() => {
    conf.clear(SWITCH);
  });

  it('should be off by default', () => {
    expect(isAuthenticationSecureByDefault()).toBe(false);
  });

  it('should follow the configuration', () => {
    conf.set(SWITCH, true);
    expect(isAuthenticationSecureByDefault()).toBe(true);
  });
});

// Before the password: refused without checking it, like a disabled Basic auth
describe('checkApiBasicAuthTwoFactor', () => {
  afterEach(() => {
    conf.clear(SWITCH);
  });

  describe('switch on', () => {
    beforeEach(() => {
      conf.set(SWITCH, true);
    });

    it('should refuse an account with two-factor authentication', async () => {
      await expect(checkApiBasicAuthTwoFactor({}, async () => ({ otp_activated: true }))).rejects.toThrow(USE_API_TOKEN);
    });

    // Applies to every account: no need to load it
    it('should refuse any account without loading it when two-factor authentication is mandatory', async () => {
      const loadAccount = vi.fn();
      await expect(checkApiBasicAuthTwoFactor({ otp_mandatory: true }, loadAccount)).rejects.toThrow(USE_API_TOKEN);
      expect(loadAccount).not.toHaveBeenCalled();
    });

    it('should accept an account without two-factor authentication', async () => {
      await expect(checkApiBasicAuthTwoFactor({ otp_mandatory: false }, async () => ({ otp_activated: false }))).resolves.toBeUndefined();
    });

    // login() refuses it, as any unknown email
    it('should accept an unknown email', async () => {
      await expect(checkApiBasicAuthTwoFactor({}, async () => undefined)).resolves.toBeUndefined();
    });
  });

  describe('switch off', () => {
    it('should accept any account without loading it', async () => {
      const loadAccount = vi.fn();
      await expect(checkApiBasicAuthTwoFactor({ otp_mandatory: true }, loadAccount)).resolves.toBeUndefined();
      expect(loadAccount).not.toHaveBeenCalled();
    });
  });
});

// After a successful login, while the switch is off
describe('warnApiBasicAuthTwoFactor', () => {
  let userCount = 0;
  // A new id for each test: the warning is rate limited per user
  const newUserId = () => {
    userCount += 1;
    return `two-factor-user-${userCount}`;
  };
  const twoFactorWarnings = () => vi.mocked(logApp.warn).mock.calls.filter(([message]) => String(message).includes(SWITCH));

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    conf.clear(SWITCH);
    vi.useRealTimers();
  });

  it('should warn with the id only for an account with two-factor authentication', () => {
    const id = newUserId();
    warnApiBasicAuthTwoFactor({ id, otp_activated: true }, {});
    expect(twoFactorWarnings()).toEqual([[expect.any(String), { user_id: id }]]);
  });

  it('should warn when two-factor authentication is mandatory', () => {
    const id = newUserId();
    warnApiBasicAuthTwoFactor({ id, otp_activated: false }, { otp_mandatory: true });
    expect(twoFactorWarnings()).toEqual([[expect.any(String), { user_id: id }]]);
  });

  it('should not warn for an account without two-factor authentication', () => {
    warnApiBasicAuthTwoFactor({ id: newUserId() }, {});
    expect(twoFactorWarnings()).toHaveLength(0);
  });

  // The request was refused before: nothing to migrate is accepted
  it('should not warn when the switch is on', () => {
    conf.set(SWITCH, true);
    warnApiBasicAuthTwoFactor({ id: newUserId(), otp_activated: true }, {});
    expect(twoFactorWarnings()).toHaveLength(0);
  });

  it('should warn at most once per user per hour', () => {
    vi.useFakeTimers();
    const id = newUserId();
    const otherId = newUserId();
    warnApiBasicAuthTwoFactor({ id, otp_activated: true }, {});
    vi.advanceTimersByTime(HOUR_MS - 1);
    warnApiBasicAuthTwoFactor({ id, otp_activated: true }, {});
    // Another user has its own hour
    warnApiBasicAuthTwoFactor({ id: otherId, otp_activated: true }, {});
    expect(twoFactorWarnings()).toEqual([[expect.any(String), { user_id: id }], [expect.any(String), { user_id: otherId }]]);
    vi.advanceTimersByTime(1);
    warnApiBasicAuthTwoFactor({ id, otp_activated: true }, {});
    expect(twoFactorWarnings()).toHaveLength(3);
  });
});

describe('authenticateUserByBasicAuth with the setting', () => {
  const context = { user: SYSTEM_USER, req: {} } as unknown as AuthContext;
  const req = { headers: {}, header: () => undefined, ip: '127.0.0.1' } as unknown as Parameters<typeof authenticateUserByBasicAuth>[1];
  const BYPASS_USER = { id: 'bypass-user-id', user_email: 'bypass@opencti.io', capabilities: [{ name: BYPASS }] };
  const credentials = { username: BYPASS_USER.user_email, password: 'right-password' };
  const wrongCredentials = { ...credentials, password: 'wrong-password' };

  const mockSettings = (settings: BasicAuthSettings) => {
    vi.mocked(Cache.getEntityFromCache).mockResolvedValue(settings as never);
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[BYPASS_USER.id, BYPASS_USER]]) as never);
  };
  // A BYPASS account that logs in with the right password, without the lockout, which needs Redis
  const mockAccount = (account: Record<string, unknown>, settings: BasicAuthSettings = {}) => {
    const user = { ...BYPASS_USER, account_status: 'Active', ...account };
    vi.mocked(Cache.getEntityFromCache).mockResolvedValue({ api_basic_auth_enabled: true, local_auth_lockout_enabled: false, ...settings } as never);
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[user.id, user]]) as never);
    vi.mocked(Engine.elLoadBy).mockResolvedValue({ ...user, password: bcrypt.hashSync(credentials.password) } as never);
  };
  const twoFactorWarnings = () => vi.mocked(logApp.warn).mock.calls.filter(([message]) => String(message).includes(SWITCH));

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    conf.clear(SWITCH);
  });

  // The refusal does not depend on the account: it comes before the account is even loaded, so BYPASS cannot get through
  it('should refuse a BYPASS user before loading the account or checking the password', async () => {
    mockSettings({ api_basic_auth_enabled: false });
    await expect(authenticateUserByBasicAuth(context, req, credentials)).rejects.toThrow(USE_API_TOKEN);
    // login() loads the user first: it was never reached, so the attempt is not counted either
    expect(Engine.elLoadBy).not.toHaveBeenCalled();
    expect(Cache.getEntitiesMapFromCache).not.toHaveBeenCalled();
  });

  it('should check the password when the setting is enabled', async () => {
    mockSettings({ api_basic_auth_enabled: true });
    // No user is found, so login() refuses the credentials
    await expect(authenticateUserByBasicAuth(context, req, credentials)).rejects.toThrow('Bad login or password');
    expect(Engine.elLoadBy).toHaveBeenCalled();
  });

  it('should refuse a BYPASS user before loading the account when two-factor authentication is mandatory and the switch is on', async () => {
    conf.set(SWITCH, true);
    mockSettings({ api_basic_auth_enabled: true, otp_mandatory: true });
    await expect(authenticateUserByBasicAuth(context, req, credentials)).rejects.toThrow(USE_API_TOKEN);
    expect(Engine.elLoadBy).not.toHaveBeenCalled();
    expect(Cache.getEntitiesMapFromCache).not.toHaveBeenCalled();
  });

  // The same refusal with a wrong password: the password is never checked, and login() never reached
  it('should refuse a BYPASS user with two-factor authentication before checking the password when the switch is on', async () => {
    conf.set(SWITCH, true);
    mockAccount({ otp_activated: true });
    await expect(authenticateUserByBasicAuth(context, req, wrongCredentials)).rejects.toThrow(USE_API_TOKEN);
    await expect(authenticateUserByBasicAuth(context, req, credentials)).rejects.toThrow(USE_API_TOKEN);
    // Loaded once per request to check it, never a second time by login()
    expect(Engine.elLoadBy).toHaveBeenCalledTimes(2);
    expect(Cache.getEntitiesMapFromCache).not.toHaveBeenCalled();
  });

  it('should accept a BYPASS user with two-factor authentication and warn when the switch is off', async () => {
    mockAccount({ otp_activated: true });
    const user = await authenticateUserByBasicAuth(context, req, credentials);
    expect(user.id).toEqual(BYPASS_USER.id);
    expect(twoFactorWarnings()).toEqual([[expect.any(String), { user_id: BYPASS_USER.id }]]);
  });

  // Warned after a successful login only. Another id, as the warning is rate limited per user
  it('should not warn when the login is refused after the password', async () => {
    mockAccount({ id: 'inactive-user-id', otp_activated: true, account_status: 'Inactive' });
    await expect(authenticateUserByBasicAuth(context, req, credentials)).rejects.toThrow();
    expect(twoFactorWarnings()).toHaveLength(0);
  });
});
