import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { v4 as uuid } from 'uuid';
import type Express from 'express';
import { ADMIN_API_TOKEN, ADMIN_USER, API_EMAIL, API_PASSWORD, testContext } from '../../../utils/testQuery';
import * as conf from '../../../../src/config/conf';
import * as cache from '../../../../src/database/cache';
import { getClientBase, localAuthLockoutKeys, redisSetForgotPasswordOtp } from '../../../../src/database/redis';
import { patchAttribute } from '../../../../src/database/middleware';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { getSettingsFromDatabase } from '../../../../src/domain/settings';
import { updateLocalAuth } from '../../../../src/domain/setting-auth';
import {
  addUser,
  authenticateUserByBasicAuth,
  authenticateUserFromRequest,
  getUserByEmail,
  login,
  otpUserLogin,
  sessionAuthenticateUser,
  sessionLogin,
  userDelete,
  userEditField,
} from '../../../../src/modules/user/user-domain';
import { verifyMfa } from '../../../../src/modules/auth/auth-domain';
import { AuthType, EnvStrategyType, PROVIDERS } from '../../../../src/modules/authenticationProvider/providers-configuration';
import { ENTITY_TYPE_SETTINGS } from '../../../../src/schema/internalObject';
import { ENTITY_TYPE_USER } from '../../../../src/modules/user/user-types';
import { hashSHA256 } from '../../../../src/utils/hash';
import { normalizeEmail } from '../../../../src/utils/email';
import { totp } from '../../../../src/utils/totp';
import type { BasicStoreSettings } from '../../../../src/types/settings';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

// Policy used by most tests: 3 attempts, 15 s first lock, 60 s max lock, final action for the whole 60 min window
const WINDOW_SECONDS = 3600;
const LOCKOUT_POLICY = {
  local_auth_lockout_enabled: true,
  local_auth_lockout_max_attempts: 3,
  local_auth_lockout_final_action: 'temporary',
  local_auth_lockout_window: 60,
  local_auth_lockout_duration: 15,
  local_auth_lockout_max_duration: 60,
};
// A null value removes the stored value, so the default is returned again
const RESET_LOCKOUT_POLICY = {
  local_auth_lockout_enabled: null,
  local_auth_lockout_max_attempts: null,
  local_auth_lockout_final_action: null,
  local_auth_lockout_window: null,
  local_auth_lockout_duration: null,
  local_auth_lockout_max_duration: null,
};

const LOCKOUT_USER = { email: 'lockout-user@opencti.io', password: 'lockout-password' };
const INACTIVE_USER = { email: 'lockout-inactive@opencti.io', password: 'lockout-password' };
const EXPIRED_USER = { email: 'lockout-expired@opencti.io', password: 'lockout-password' };
const MFA_USER = { email: 'lockout-mfa@opencti.io', password: 'lockout-password' };
const EXTERNAL_USER = { email: 'lockout-external@opencti.io', password: 'lockout-password' };
const SERVICE_ACCOUNT_EMAIL = 'lockout-service-account@opencti.io';
const UNKNOWN_EMAIL = 'lockout-unknown@opencti.io';
const WRONG_PASSWORD = 'wrong-password';
const ALL_EMAILS = [LOCKOUT_USER.email, INACTIVE_USER.email, EXPIRED_USER.email, MFA_USER.email, EXTERNAL_USER.email, SERVICE_ACCOUNT_EMAIL, UNKNOWN_EMAIL, API_EMAIL];

// region helpers
const keysOf = (email: string) => localAuthLockoutKeys(hashSHA256(normalizeEmail(email)));
const resetLockout = (email: string) => {
  const keys = keysOf(email);
  return getClientBase().del(keys.failures, keys.lock);
};
// Redis TTLs cannot be faked, so expirations are simulated by deleting the keys
const expireLock = (email: string) => getClientBase().del(keysOf(email).lock);
const expireWindow = (email: string) => getClientBase().del(keysOf(email).failures);
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

const setLockoutPolicy = async (policy: Record<string, boolean | number | string | null>) => {
  const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
  await updateLocalAuth(testContext, ADMIN_USER, settings.id, { enabled: true, ...policy } as Parameters<typeof updateLocalAuth>[3]);
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
};

const expectBadCredentials = async (promise: Promise<unknown>) => {
  const error = await promise.then(() => undefined, (e) => e);
  expect(error).toBeDefined();
  expect(error.extensions?.code).toEqual('AUTH_FAILURE');
  expect(error.extensions?.data?.lock).toBeUndefined();
};
const expectLocked = async (promise: Promise<unknown>, remainingSeconds: number) => {
  await expect(promise).rejects.toMatchObject({
    extensions: { code: 'AUTH_FAILURE', data: { lock: 'temporary', remaining_seconds: remainingSeconds } },
  });
};
const expectPermanentlyLocked = async (promise: Promise<unknown>) => {
  await expect(promise).rejects.toMatchObject({
    message: conf.ACCOUNT_STATUSES.Locked,
    extensions: { code: 'AUTH_FAILURE', data: { lock: 'permanent' } },
  });
};
// Each failure locks the email: the lock is lifted after each one, so that the next attempt is counted
const failLogin = async (email: string, times: number) => {
  for (let i = 0; i < times; i += 1) {
    const error = await login(email, WRONG_PASSWORD).then(() => undefined, (e) => e);
    expect(error?.extensions?.data?.lock).toBeDefined();
    await expireLock(email);
  }
};
const accountStatusOf = async (email: string) => (await getUserByEmail(email))?.account_status;

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
// A full login through the login form: login() alone counts the attempt, only an accepted login clears the lockout
const sessionLoginAs = (email: string, password: string) => sessionLogin(buildSessionContext(), { email, password });
// Settings from the cache with the IP whitelist enabled, the test requests coming from another IP
const enableIpWhitelist = () => {
  const getEntityFromCache = cache.getEntityFromCache;
  vi.spyOn(cache, 'getEntityFromCache').mockImplementation(async (context, user, type) => {
    const entity = await getEntityFromCache(context, user, type);
    return type === ENTITY_TYPE_SETTINGS ? { ...entity, platform_ip_whitelist_enabled: true, platform_ip_whitelist: ['10.10.10.10'] } : entity;
  });
};
// endregion

describe('Local authentication lockout', () => {
  const createdUserIds: string[] = [];
  let lockoutUserId: string;
  let mfaUserId: string;
  let mfaSecret: string;

  beforeAll(async () => {
    for (const { email, password } of [LOCKOUT_USER, INACTIVE_USER, EXPIRED_USER, MFA_USER]) {
      const user = await addUser(testContext, ADMIN_USER, { user_email: email, name: email, password });
      createdUserIds.push(user.id);
    }
    [lockoutUserId, , , mfaUserId] = createdUserIds;
    const externalUser = await addUser(testContext, ADMIN_USER, { user_email: EXTERNAL_USER.email, name: EXTERNAL_USER.email, password: EXTERNAL_USER.password, external: true });
    const serviceAccount = await addUser(testContext, ADMIN_USER, { user_email: SERVICE_ACCOUNT_EMAIL, name: SERVICE_ACCOUNT_EMAIL, user_service_account: true });
    createdUserIds.push(externalUser.id, serviceAccount.id);
    await userEditField(testContext, ADMIN_USER, createdUserIds[1], [{ key: 'account_status', value: ['Inactive'] }]);
    await userEditField(testContext, ADMIN_USER, createdUserIds[2], [{ key: 'account_lock_after_date', value: ['2020-01-01T00:00:00.000Z'] }]);
    mfaSecret = totp.generateSecret();
    await patchAttribute(testContext, ADMIN_USER, mfaUserId, ENTITY_TYPE_USER, { otp_activated: true, otp_secret: mfaSecret });
    resetCacheForEntity(ENTITY_TYPE_USER);
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
      for (let i = 0; i < 5; i += 1) {
        await expectBadCredentials(login(LOCKOUT_USER.email, WRONG_PASSWORD));
      }
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should not lock when the lockout is disabled in the settings', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_enabled: false });
      for (let i = 0; i < 5; i += 1) {
        await expectBadCredentials(login(LOCKOUT_USER.email, WRONG_PASSWORD));
      }
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });
  });

  describe('Temporary locks', () => {
    it('should lock from the first failure, with a duration doubled on each failure', async () => {
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expireLock(LOCKOUT_USER.email);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 30);
    });

    it('should cap the duration to the max duration', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_max_attempts: 10 });
      for (const expectedSeconds of [15, 30, 60, 60]) {
        await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), expectedSeconds);
        await expireLock(LOCKOUT_USER.email);
      }
    });

    it('should allow the correct password once the lock has expired', async () => {
      await failLogin(LOCKOUT_USER.email, 1);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should lock an unknown email exactly like a real account', async () => {
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD), 15);
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD), 15);
      await expireLock(UNKNOWN_EMAIL);
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD), 30);
    });

    it('should share the counter between email case variants', async () => {
      await failLogin(LOCKOUT_USER.email, 1);
      await expectLocked(login(LOCKOUT_USER.email.toUpperCase(), WRONG_PASSWORD), 30);
    });

    it('should check one password at most under concurrent attempts', async () => {
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      const attempts = Array.from({ length: 20 }, () => login(LOCKOUT_USER.email, WRONG_PASSWORD).catch((e) => e));
      const errors = await Promise.all(attempts);
      expect(compareSpy).toHaveBeenCalledTimes(1);
      expect(errors.filter((e) => e.extensions?.data?.remaining_seconds === 15)).toHaveLength(20);
    });
  });

  describe('During a lock', () => {
    it('should reject the correct password without checking it', async () => {
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), 15);
      expect(compareSpy).not.toHaveBeenCalled();
    });

    it('should neither count the attempts nor extend the lock', async () => {
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      const remainingBefore = await lockRemainingMs(LOCKOUT_USER.email);
      for (let i = 0; i < 5; i += 1) {
        await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      }
      expect(await lockRemainingMs(LOCKOUT_USER.email)).toBeLessThanOrEqual(remainingBefore);
      // The next failure is only the second one
      await expireLock(LOCKOUT_USER.email);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 30);
    });

    it('should return the lock error through sessionLogin', async () => {
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await expectLocked(sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password), 15);
    });
  });

  // The window is fixed: it starts on the first failure and is never extended
  describe('Failure window', () => {
    it('should start the counter again from zero when the window has expired', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expireWindow(LOCKOUT_USER.email);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });

    it('should not extend the window on the next failures', async () => {
      const { failures } = keysOf(LOCKOUT_USER.email);
      await failLogin(LOCKOUT_USER.email, 1);
      await shortenTtl(failures);
      await failLogin(LOCKOUT_USER.email, 1);
      await expectTtlNotExtended(failures);
    });
  });

  describe('Final action: temporary', () => {
    it('should lock for the whole window once the max attempts are reached, without changing the account status', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), WINDOW_SECONDS);
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), WINDOW_SECONDS);
      expect(await accountStatusOf(LOCKOUT_USER.email)).toEqual('Active');
    });

    it('should allow the login again once the final lock and the window are over', async () => {
      await failLogin(LOCKOUT_USER.email, 3);
      await expireWindow(LOCKOUT_USER.email);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });
  });

  describe('Final action: permanent', () => {
    beforeEach(async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_final_action: 'permanent' });
    });

    afterEach(async () => {
      if (await accountStatusOf(LOCKOUT_USER.email) !== 'Active') {
        await userEditField(testContext, ADMIN_USER, lockoutUserId, [{ key: 'account_status', value: ['Active'] }]);
      }
    });

    it('should set the account to Locked once the max attempts are reached', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      expect(await accountStatusOf(LOCKOUT_USER.email)).toEqual('Active');
      await expectPermanentlyLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD));
      expect(await accountStatusOf(LOCKOUT_USER.email)).toEqual('Locked');
    });

    it('should reject the correct password without checking it', async () => {
      await failLogin(LOCKOUT_USER.email, 3);
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectPermanentlyLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password));
      expect(compareSpy).not.toHaveBeenCalled();
    });

    it('should stay locked when the lock and the window are over', async () => {
      await failLogin(LOCKOUT_USER.email, 3);
      await expireWindow(LOCKOUT_USER.email);
      await expect(login(LOCKOUT_USER.email, LOCKOUT_USER.password)).rejects.toBeDefined();
      expect(await accountStatusOf(LOCKOUT_USER.email)).toEqual('Locked');
    });

    it('should reject the API tokens of a locked account', async () => {
      await failLogin(API_EMAIL, 3);
      try {
        const tokenUser = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: `Bearer ${ADMIN_API_TOKEN}` }));
        expect(tokenUser).toBeUndefined();
      } finally {
        await userEditField(testContext, ADMIN_USER, ADMIN_USER.id, [{ key: 'account_status', value: ['Active'] }]);
      }
    });

    it('should unlock the account when an administrator sets it back to Active', async () => {
      await failLogin(LOCKOUT_USER.email, 3);
      await userEditField(testContext, ADMIN_USER, lockoutUserId, [{ key: 'account_status', value: ['Active'] }]);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should report a permanent lock on an unknown email exactly like on a real account', async () => {
      await failLogin(UNKNOWN_EMAIL, 2);
      await expectPermanentlyLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
      await expectPermanentlyLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
    });

    it.each([
      ['a service account', SERVICE_ACCOUNT_EMAIL],
      ['an external user', EXTERNAL_USER.email],
    ])('should never set %s to Locked, with the same messages', async (_, email) => {
      await failLogin(email, 2);
      await expectPermanentlyLocked(login(email, WRONG_PASSWORD));
      expect(await accountStatusOf(email)).toEqual('Active');
    });
  });

  describe('Successful login', () => {
    it('should reset the failure counter', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });

    it('should reset the lockout on an SSO login', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      // OIDC, SAML, certificate and headers logins all end with a session login
      await sessionAuthenticateUser(testContext, buildRequest(), { id: lockoutUserId, internal_id: lockoutUserId }, 'oidc');
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
    });

    it('should reset the lockout when an administrator sets the account back to Active', async () => {
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      await userEditField(testContext, ADMIN_USER, lockoutUserId, [{ key: 'account_status', value: ['Active'] }]);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should count the attempt when the password is right but the IP is not allowed', async () => {
      await failLogin(LOCKOUT_USER.email, 1);
      enableIpWhitelist();
      await expect(sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password)).rejects.toThrow('Your IP address is not allowed to access this platform');
      vi.restoreAllMocks();
      // The rejected login was the second attempt
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), 30);
    });

    it('should count the attempt when the password is right but the local auth is disabled', async () => {
      await failLogin(LOCKOUT_USER.email, 1);
      const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
      await updateLocalAuth(testContext, ADMIN_USER, settings.id, { enabled: false });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
      await expectBadCredentials(sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password));
      // The rejected login was the second attempt
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password), 30);
    });
  });

  describe('Inactive, expired and service accounts', () => {
    it.each([
      ['inactive', INACTIVE_USER.email, INACTIVE_USER.password],
      ['expired', EXPIRED_USER.email, EXPIRED_USER.password],
      ['service', SERVICE_ACCOUNT_EMAIL, 'any-password'],
    ])('should not check the password of an %s account', async (_, email, password) => {
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectLocked(login(email, password), 15);
      expect(compareSpy).not.toHaveBeenCalled();
    });
  });

  describe('Admin from configuration', () => {
    it('should lock the admin from configuration like any other user', async () => {
      await expectLocked(login(API_EMAIL, WRONG_PASSWORD), 15);
      await expectLocked(login(API_EMAIL, API_PASSWORD), 15);
    });
  });

  describe('API access', () => {
    it('should count Basic auth failures and reject a locked account in Basic auth', async () => {
      const basicAuth = (password: string) => authenticateUserByBasicAuth(testContext, buildRequest(), { username: LOCKOUT_USER.email, password });
      await expectLocked(basicAuth(WRONG_PASSWORD), 15);
      await expectLocked(basicAuth(LOCKOUT_USER.password), 15);
      await expireLock(LOCKOUT_USER.email);
      await expectLocked(basicAuth(WRONG_PASSWORD), 30);
    });

    it('should reset the failure counter on a successful Basic auth', async () => {
      await failLogin(API_EMAIL, 2);
      const user = await authenticateUserByBasicAuth(testContext, buildRequest(), { username: API_EMAIL, password: API_PASSWORD });
      expect(user.id).toEqual(ADMIN_USER.id);
      await expectLocked(login(API_EMAIL, WRONG_PASSWORD), 15);
    });

    it('should keep API tokens and open sessions working during a temporary lock', async () => {
      const basicHeader = `Basic ${Buffer.from(`${API_EMAIL}:${API_PASSWORD}`).toString('base64')}`;
      // Sanity check: Basic auth works before the lock
      const beforeLock = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: basicHeader }));
      expect(beforeLock?.id).toEqual(ADMIN_USER.id);
      // Lock the admin
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

  // Failed MFA codes count like failed passwords, so that the second factor cannot be brute-forced
  describe('MFA', () => {
    const mfaUser = () => ({ id: mfaUserId, user_email: MFA_USER.email, otp_activated: true, otp_secret: mfaSecret }) as AuthUser;
    const otpLogin = (code: string) => otpUserLogin({ session: { user: {}, save: () => {} } }, mfaUser(), { code });
    const validCode = () => totp.generate({ secret: mfaSecret });
    // Any other 6 digits code than the valid one
    const wrongCode = async () => {
      const code = await validCode();
      return `${code.slice(0, 5)}${(Number(code[5]) + 1) % 10}`;
    };

    it('should count a failed MFA code like a failed password', async () => {
      await expectLocked(otpLogin(await wrongCode()), 15);
      await expireLock(MFA_USER.email);
      await expectLocked(login(MFA_USER.email, WRONG_PASSWORD), 30);
    });

    it('should reject a valid MFA code during a lock', async () => {
      await expectLocked(otpLogin(await wrongCode()), 15);
      await expectLocked(otpLogin(await validCode()), 15);
    });

    it('should reset the counter after a valid MFA code', async () => {
      await expectLocked(otpLogin(await wrongCode()), 15);
      await expireLock(MFA_USER.email);
      expect(await otpLogin(await validCode())).toBe(true);
      await expectLocked(otpLogin(await wrongCode()), 15);
    });

    it('should not reset the counter on a right password alone', async () => {
      await expectLocked(otpLogin(await wrongCode()), 15);
      await expireLock(MFA_USER.email);
      // The right password lifts its own attempt, but keeps the failure of the MFA code
      await sessionLoginAs(MFA_USER.email, MFA_USER.password);
      expect(await getClientBase().exists(keysOf(MFA_USER.email).lock)).toEqual(0);
      await expectLocked(otpLogin(await wrongCode()), 30);
    });

    it('should set the account to Locked with the permanent final action', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_final_action: 'permanent' });
      try {
        for (let i = 0; i < 2; i += 1) {
          await expectLocked(otpLogin(await wrongCode()), 15 * (2 ** i));
          await expireLock(MFA_USER.email);
        }
        await expectPermanentlyLocked(otpLogin(await wrongCode()));
        expect(await accountStatusOf(MFA_USER.email)).toEqual('Locked');
      } finally {
        await userEditField(testContext, ADMIN_USER, mfaUserId, [{ key: 'account_status', value: ['Active'] }]);
      }
    });

    it('should count a failed MFA code in the forgotten password flow', async () => {
      const transactionId = uuid();
      await redisSetForgotPasswordOtp(transactionId, { email: MFA_USER.email, hashedOtp: bcrypt.hashSync('12345678'), mfa_activated: true, mfa_validated: false, userId: mfaUserId });
      await expectLocked(verifyMfa(testContext, { transactionId, code: await wrongCode() }), 15);
      await expectLocked(verifyMfa(testContext, { transactionId, code: await validCode() }), 15);
      await expireLock(MFA_USER.email);
      expect(await verifyMfa(testContext, { transactionId, code: await validCode() })).toBe(true);
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
          this.success({ id: lockoutUserId, internal_id: lockoutUserId });
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
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 15);
      // The LDAP login is never blocked by the local lock
      await sessionLogin(buildSessionContext(), { email: LOCKOUT_USER.email, password: 'ldap-password' });
      // Any successful login deletes every key for this email
      expect(await getClientBase().exists(keysOf(LOCKOUT_USER.email).lock)).toEqual(0);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should return the generic error instead of the local lock when another form provider exists', async () => {
      // The fake LDAP rejects this email, as LDAP would reject a wrong password
      await expectBadCredentials(sessionLoginAs(UNKNOWN_EMAIL, WRONG_PASSWORD));
      // The local lock exists, it is just not shown
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD), 15);
    });
  });
});
