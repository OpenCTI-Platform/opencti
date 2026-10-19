import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import type Express from 'express';
import { ADMIN_API_TOKEN, ADMIN_USER, API_EMAIL, API_PASSWORD, testContext } from '../../../utils/testQuery';
import * as conf from '../../../../src/config/conf';
import { getClientBase, localAuthLockoutKeys } from '../../../../src/database/redis';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { getSettingsFromDatabase } from '../../../../src/domain/settings';
import { updateLocalAuth } from '../../../../src/domain/setting-auth';
import { addUser, authenticateUserByBasicAuth, authenticateUserFromRequest, login, sessionLogin, userDelete, userEditField } from '../../../../src/modules/user/user-domain';
import { AuthType, EnvStrategyType, PROVIDERS } from '../../../../src/modules/authenticationProvider/providers-configuration';
import { ENTITY_TYPE_SETTINGS } from '../../../../src/schema/internalObject';
import { hashSHA256 } from '../../../../src/utils/hash';
import { normalizeEmail } from '../../../../src/utils/email';
import type { BasicStoreSettings } from '../../../../src/types/settings';
import type { AuthContext } from '../../../../src/types/user';

// Policy used by most tests: 3 attempts, 15 min first lock, 180 min max lock
const LOCKOUT_POLICY = {
  local_auth_lockout_enabled: true,
  local_auth_lockout_max_attempts: 3,
  local_auth_lockout_window: 60,
  local_auth_lockout_duration: 15,
  local_auth_lockout_max_duration: 180,
};
// A null value removes the stored value, so the default is returned again
const RESET_LOCKOUT_POLICY = {
  local_auth_lockout_enabled: null,
  local_auth_lockout_max_attempts: null,
  local_auth_lockout_window: null,
  local_auth_lockout_duration: null,
  local_auth_lockout_max_duration: null,
};

const LOCKOUT_USER = { email: 'lockout-user@opencti.io', password: 'lockout-password' };
const INACTIVE_USER = { email: 'lockout-inactive@opencti.io', password: 'lockout-password' };
const EXPIRED_USER = { email: 'lockout-expired@opencti.io', password: 'lockout-password' };
const UNKNOWN_EMAIL = 'lockout-unknown@opencti.io';
const WRONG_PASSWORD = 'wrong-password';
const ALL_EMAILS = [LOCKOUT_USER.email, INACTIVE_USER.email, EXPIRED_USER.email, UNKNOWN_EMAIL, API_EMAIL];

// region helpers
const keysOf = (email: string) => localAuthLockoutKeys(hashSHA256(normalizeEmail(email)));
const resetLockout = (email: string) => {
  const keys = keysOf(email);
  return getClientBase().del(keys.failures, keys.lock, keys.level);
};
// Redis TTLs cannot be faked, so expirations are simulated by deleting the keys
const expireLock = (email: string) => getClientBase().del(keysOf(email).lock);
// The lock level expires with the failure counter: same window, counted from the first failure
const expireWindow = (email: string) => {
  const keys = keysOf(email);
  return getClientBase().del(keys.failures, keys.level);
};
const lockRemainingMs = (email: string) => getClientBase().pttl(keysOf(email).lock);
// Shortens a key TTL, so that a TTL reset to the full window can be told apart from the original one
const SHORT_TTL_MS = 30000;
const shortenTtl = (key: string) => getClientBase().pexpire(key, SHORT_TTL_MS);
const expectTtlNotExtended = async (key: string) => {
  const remainingMs = await getClientBase().pttl(key);
  // pttl returns a negative value when the key does not exist or has no TTL
  expect(remainingMs).toBeGreaterThan(0);
  expect(remainingMs).toBeLessThanOrEqual(SHORT_TTL_MS);
};

const setLockoutPolicy = async (policy: Record<string, boolean | number | null>) => {
  const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
  await updateLocalAuth(testContext, ADMIN_USER, settings.id, { enabled: true, ...policy });
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
};

const expectBadCredentials = async (promise: Promise<unknown>) => {
  const error = await promise.then(() => undefined, (e) => e);
  expect(error).toBeDefined();
  expect(error.extensions?.code).toEqual('AUTH_FAILURE');
  expect(error.extensions?.data?.remaining_minutes).toBeUndefined();
};
const expectLocked = async (promise: Promise<unknown>, remainingMinutes: number) => {
  await expect(promise).rejects.toMatchObject({
    extensions: { code: 'AUTH_FAILURE', data: { remaining_minutes: remainingMinutes } },
  });
};
const failLogin = async (email: string, times: number) => {
  for (let i = 0; i < times; i += 1) {
    await expectBadCredentials(login(email, WRONG_PASSWORD));
  }
};

const buildRequest = (headers: Record<string, string> = {}) => ({
  ip: '127.0.0.1',
  headers: { 'x-forwarded-for': '127.0.0.1', ...headers },
  header: (_: string) => undefined,
  session: {
    regenerate: (callback: (err: unknown) => void) => callback(null),
    save: () => {},
  },
}) as unknown as Express.Request;
const buildApiRequest = (headers: Record<string, string> = {}, session?: { user: { id: string } }) => (
  { ...buildRequest(headers), session } as unknown as Parameters<typeof authenticateUserFromRequest>[1]
);
const buildSessionContext = () => ({
  otp_mandatory: false,
  req: buildRequest(),
  source: '',
  user: undefined,
  user_inside_platform_organization: false,
}) as AuthContext;
// endregion

describe('Local authentication lockout', () => {
  const createdUserIds: string[] = [];

  beforeAll(async () => {
    for (const { email, password } of [LOCKOUT_USER, INACTIVE_USER, EXPIRED_USER]) {
      const user = await addUser(testContext, ADMIN_USER, { user_email: email, name: email, password });
      createdUserIds.push(user.id);
    }
    await userEditField(testContext, ADMIN_USER, createdUserIds[1], [{ key: 'account_status', value: ['Inactive'] }]);
    await userEditField(testContext, ADMIN_USER, createdUserIds[2], [{ key: 'account_lock_after_date', value: ['2020-01-01T00:00:00.000Z'] }]);
  });

  beforeEach(async () => {
    await setLockoutPolicy(LOCKOUT_POLICY);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await Promise.all(ALL_EMAILS.map(resetLockout));
  });

  afterAll(async () => {
    await setLockoutPolicy(RESET_LOCKOUT_POLICY);
    for (const userId of createdUserIds) {
      await userDelete(testContext, ADMIN_USER, userId);
    }
  });

  describe('Activation', () => {
    it('should not lock when the feature flag is disabled', async () => {
      vi.spyOn(conf, 'isFeatureEnabled').mockReturnValue(false);
      await failLogin(LOCKOUT_USER.email, 5);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should not lock when the lockout is disabled in the settings', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_enabled: false });
      await failLogin(LOCKOUT_USER.email, 5);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });
  });

  describe('Failure counter', () => {
    it('should not lock after X-1 failures', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should lock after X failures with the remaining minutes', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });

    it('should lock an unknown email exactly like a real account', async () => {
      await failLogin(UNKNOWN_EMAIL, 2);
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD), 15);
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD), 15);
    });

    it('should share the counter between email case variants', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email.toUpperCase(), WRONG_PASSWORD), 15);
    });

    it('should lock only once under concurrent attempts', async () => {
      const attempts = Array.from({ length: 10 }, () => login(LOCKOUT_USER.email, WRONG_PASSWORD).catch((e) => e));
      const errors = await Promise.all(attempts);
      expect(errors.every((e) => e.extensions?.code === 'AUTH_FAILURE')).toBe(true);
      // Still on the first lock level
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), 15);
      // The next lock is the second level, not a higher one
      await expireLock(LOCKOUT_USER.email);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 30);
    });
  });

  // The window is fixed: it starts on the first failure and is never extended
  describe('Failure window', () => {
    it('should start the counter again from zero when the window has expired', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expireWindow(LOCKOUT_USER.email);
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });

    it('should not extend the window on the next failures', async () => {
      const { failures } = keysOf(LOCKOUT_USER.email);
      await failLogin(LOCKOUT_USER.email, 1);
      await shortenTtl(failures);
      await failLogin(LOCKOUT_USER.email, 1);
      await expectTtlNotExtended(failures);
    });

    it('should make the lock level expire with the window, even after a new lock', async () => {
      const { failures, level } = keysOf(LOCKOUT_USER.email);
      await failLogin(LOCKOUT_USER.email, 1);
      await shortenTtl(failures);
      await failLogin(LOCKOUT_USER.email, 1);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expectTtlNotExtended(level);
      // A new lock in the same window does not extend it either
      await expireLock(LOCKOUT_USER.email);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 30);
      await expectTtlNotExtended(level);
    });

    it('should reset the counter and the lock level once the window has expired', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expireLock(LOCKOUT_USER.email);
      await expireWindow(LOCKOUT_USER.email);
      // The next failures count from zero: no immediate lock
      await failLogin(LOCKOUT_USER.email, 2);
      // And the next lock is back to the first level
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });

    it('should not lift a lock in progress when the window expires', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expireWindow(LOCKOUT_USER.email);
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), 15);
      // Once the lock is over, the first failure counts as the first one
      await expireLock(LOCKOUT_USER.email);
      await expectBadCredentials(login(LOCKOUT_USER.email, WRONG_PASSWORD));
    });
  });

  describe('During a lock', () => {
    it('should reject the correct password without checking it', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), 15);
      expect(compareSpy).not.toHaveBeenCalled();
    });

    it('should not extend the lock', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      const remainingBefore = await lockRemainingMs(LOCKOUT_USER.email);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), 15);
      const remainingAfter = await lockRemainingMs(LOCKOUT_USER.email);
      expect(remainingAfter).toBeLessThanOrEqual(remainingBefore);
    });

    it('should return the lock error through sessionLogin', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expectLocked(sessionLogin(buildSessionContext(), { email: LOCKOUT_USER.email, password: LOCKOUT_USER.password }), 15);
    });
  });

  describe('After a lock', () => {
    it('should lock again on the first failure within the window, with a doubled duration up to the max duration', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      for (const expectedMinutes of [30, 60, 120, 180, 180]) {
        await expireLock(LOCKOUT_USER.email);
        await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), expectedMinutes);
      }
    });

    it('should allow the correct password once the lock has expired', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expireLock(LOCKOUT_USER.email);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });
  });

  describe('Successful login', () => {
    it('should reset the failure counter', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });

    it('should reset the lock level: the next failure counts as the first one', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expireLock(LOCKOUT_USER.email);
      await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });
  });

  describe('Inactive and expired accounts', () => {
    it.each([
      ['inactive', INACTIVE_USER],
      ['expired', EXPIRED_USER],
    ])('should not check the password of an %s account', async (_, { email, password }) => {
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectBadCredentials(login(email, password));
      expect(compareSpy).not.toHaveBeenCalled();
    });
  });

  describe('Admin from configuration', () => {
    it('should lock the admin from configuration like any other user', async () => {
      await failLogin(API_EMAIL, 2);
      await expectLocked(login(API_EMAIL, WRONG_PASSWORD), 15);
      await expectLocked(login(API_EMAIL, API_PASSWORD), 15);
    });
  });

  describe('API access', () => {
    it('should count Basic auth failures and reject a locked account in Basic auth', async () => {
      const basicAuth = (password: string) => authenticateUserByBasicAuth(testContext, buildRequest(), { username: LOCKOUT_USER.email, password });
      await expectBadCredentials(basicAuth(WRONG_PASSWORD));
      await expectBadCredentials(basicAuth(WRONG_PASSWORD));
      await expectLocked(basicAuth(WRONG_PASSWORD), 15);
      await expectLocked(basicAuth(LOCKOUT_USER.password), 15);
    });

    it('should keep API tokens and open sessions working during a lock', async () => {
      const basicHeader = `Basic ${Buffer.from(`${API_EMAIL}:${API_PASSWORD}`).toString('base64')}`;
      // Sanity check: Basic auth works before the lock
      const beforeLock = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: basicHeader }));
      expect(beforeLock?.id).toEqual(ADMIN_USER.id);
      // Lock the admin
      await failLogin(API_EMAIL, 2);
      await expectLocked(login(API_EMAIL, WRONG_PASSWORD), 15);
      // Basic auth is blocked
      const basicUser = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: basicHeader }));
      expect(basicUser).toBeUndefined();
      // Bearer API token still works
      const tokenUser = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: `Bearer ${ADMIN_API_TOKEN}` }));
      expect(tokenUser?.id).toEqual(ADMIN_USER.id);
      // Open session still works
      const sessionUser = await authenticateUserFromRequest(testContext, buildApiRequest({}, { user: { id: ADMIN_USER.id } }));
      expect(sessionUser?.id).toEqual(ADMIN_USER.id);
    });
  });

  describe('LDAP and other form providers', () => {
    const FAKE_LDAP = 'fake_ldap_lockout';

    beforeEach(() => {
      // Form provider that validates the lockout user whatever the password
      class FakeLdapStrategy extends passport.Strategy {
        name = FAKE_LDAP;

        authenticate(req: Express.Request) {
          const { username } = (req as unknown as { body: { username: string } }).body;
          if (normalizeEmail(username) !== LOCKOUT_USER.email) {
            this.fail();
            return;
          }
          this.success({ id: createdUserIds[0], internal_id: createdUserIds[0] });
        }
      }
      passport.use(FAKE_LDAP, new FakeLdapStrategy());
      PROVIDERS.push({ name: FAKE_LDAP, type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LOCAL, provider: FAKE_LDAP });
    });

    afterEach(() => {
      const index = PROVIDERS.findIndex((p) => p.provider === FAKE_LDAP);
      if (index >= 0) PROVIDERS.splice(index, 1);
      passport.unuse(FAKE_LDAP);
    });

    it('should let an LDAP user log in through LDAP while the local lock exists, and clear the lock', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      // The LDAP login is never blocked by the local lock
      await sessionLogin(buildSessionContext(), { email: LOCKOUT_USER.email, password: 'ldap-password' });
      // Any successful login deletes every key for this email
      expect(await getClientBase().exists(keysOf(LOCKOUT_USER.email).lock)).toEqual(0);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });
  });
});
