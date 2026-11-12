import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import { v4 as uuid } from 'uuid';
import type Express from 'express';
import { ADMIN_USER, AMBER_GROUP, API_EMAIL, API_PASSWORD, getGroupIdByName, PLATFORM_ADMIN_GROUP, testContext } from '../../../utils/testQuery';
import * as conf from '../../../../src/config/conf';
import * as cache from '../../../../src/database/cache';
import { getClientBase, localAuthLockoutKeys, redisRecordLocalAuthAttempt, redisReleaseLocalAuthAttempt, redisSetForgotPasswordOtp } from '../../../../src/database/redis';
import { patchAttribute } from '../../../../src/database/middleware';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { getSettingsFromDatabase } from '../../../../src/domain/settings';
import { updateLocalAuth } from '../../../../src/domain/setting-auth';
import {
  addUser,
  addUserTokenByAdmin,
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
import { TokenDuration } from '../../../../src/generated/graphql';
import { ENTITY_TYPE_SETTINGS } from '../../../../src/schema/internalObject';
import { ENTITY_TYPE_USER } from '../../../../src/modules/user/user-types';
import { hashSHA256 } from '../../../../src/utils/hash';
import { normalizeEmail } from '../../../../src/utils/email';
import { totp } from '../../../../src/utils/totp';
import type { BasicStoreSettings } from '../../../../src/types/settings';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

// Policy used by most tests: 3 attempts within a 60 min window, then the final action for 10 min.
// The failures before it are only counted, without any lock
const LOCK_MINUTES = 10;
const LOCK_SECONDS = LOCK_MINUTES * 60;
const LOCKOUT_POLICY = {
  local_auth_lockout_enabled: true,
  local_auth_lockout_max_attempts: 3,
  local_auth_lockout_admin_max_attempts: 3,
  local_auth_lockout_final_action: 'temporary',
  local_auth_lockout_window: 60,
  local_auth_lockout_duration: LOCK_MINUTES,
};
// A null value removes the stored value, so the default is returned again
const RESET_LOCKOUT_POLICY = {
  local_auth_lockout_enabled: null,
  local_auth_lockout_max_attempts: null,
  local_auth_lockout_admin_max_attempts: null,
  local_auth_lockout_final_action: null,
  local_auth_lockout_window: null,
  local_auth_lockout_duration: null,
};

const LOCKOUT_USER = { email: 'lockout-user@opencti.io', password: 'lockout-password' };
const INACTIVE_USER = { email: 'lockout-inactive@opencti.io', password: 'lockout-password' };
const EXPIRED_USER = { email: 'lockout-expired@opencti.io', password: 'lockout-password' };
const MFA_USER = { email: 'lockout-mfa@opencti.io', password: 'lockout-password' };
const EXTERNAL_USER = { email: 'lockout-external@opencti.io', password: 'lockout-password' };
// A user allowed to use Basic auth and API tokens
const API_USER = { email: 'lockout-api@opencti.io', password: 'lockout-password' };
// An administrative account: SETTINGS capabilities, through the platform admin group
const ADMIN_ACCOUNT = { email: 'lockout-admin@opencti.io', password: 'lockout-password' };
const SERVICE_ACCOUNT_EMAIL = 'lockout-service-account@opencti.io';
const UNKNOWN_EMAIL = 'lockout-unknown@opencti.io';
const WRONG_PASSWORD = 'wrong-password';
const ALL_EMAILS = [
  LOCKOUT_USER.email, INACTIVE_USER.email, EXPIRED_USER.email, MFA_USER.email, EXTERNAL_USER.email, API_USER.email, ADMIN_ACCOUNT.email,
  SERVICE_ACCOUNT_EMAIL, UNKNOWN_EMAIL, API_EMAIL,
];

// region helpers
const keysOf = (email: string) => localAuthLockoutKeys(hashSHA256(normalizeEmail(email)));
const resetLockout = (email: string) => {
  const keys = keysOf(email);
  return getClientBase().del(keys.failures, keys.lock);
};
// Redis TTLs cannot be faked, so expirations are simulated by deleting the keys.
// The failures expire with the temporary lock, with or without a window, so that the count starts over once the lock is lifted
const expireLock = resetLockout;
const expireWindow = (email: string) => getClientBase().del(keysOf(email).failures);
const lockRemainingMs = (email: string) => getClientBase().pttl(keysOf(email).lock);
const failuresOf = async (email: string) => Number(await getClientBase().hget(keysOf(email).failures, 'count') ?? 0);
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
const expectLocked = async (promise: Promise<unknown>, remainingSeconds = LOCK_SECONDS) => {
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
// Below the max attempts, a failure is only counted: the usual error, without any lock
const failLogin = async (email: string, times: number) => {
  for (let i = 0; i < times; i += 1) {
    await expectBadCredentials(login(email, WRONG_PASSWORD));
  }
};
// Reaches the max attempts of the test policy (3), which applies the final action
const reachMaxAttempts = async (email: string) => {
  await failLogin(email, 2);
  const error = await login(email, WRONG_PASSWORD).then(() => undefined, (e) => e);
  expect(error?.extensions?.data?.lock).toBeDefined();
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
const enableIpWhitelist = (exclusionIds: string[] = []) => {
  const getEntityFromCache = cache.getEntityFromCache;
  vi.spyOn(cache, 'getEntityFromCache').mockImplementation(async (context, user, type) => {
    const entity = await getEntityFromCache(context, user, type);
    return type === ENTITY_TYPE_SETTINGS
      ? { ...entity, platform_ip_whitelist_enabled: true, platform_ip_whitelist: ['10.10.10.10'], platform_ip_whitelist_exclusion_ids: exclusionIds }
      : entity;
  });
};
const IP_NOT_ALLOWED = 'Your IP address is not allowed to access this platform';
// endregion

describe('Local authentication lockout', () => {
  const createdUserIds: string[] = [];
  let lockoutUserId: string;
  let mfaUserId: string;
  let mfaSecret: string;
  let apiUserId: string;
  let apiUserToken: string;

  beforeAll(async () => {
    for (const { email, password } of [LOCKOUT_USER, INACTIVE_USER, EXPIRED_USER, MFA_USER]) {
      const user = await addUser(testContext, ADMIN_USER, { user_email: email, name: email, password });
      createdUserIds.push(user.id);
    }
    [lockoutUserId, , , mfaUserId] = createdUserIds;
    const externalUser = await addUser(testContext, ADMIN_USER, { user_email: EXTERNAL_USER.email, name: EXTERNAL_USER.email, password: EXTERNAL_USER.password, external: true });
    const serviceAccount = await addUser(testContext, ADMIN_USER, { user_email: SERVICE_ACCOUNT_EMAIL, name: SERVICE_ACCOUNT_EMAIL, user_service_account: true });
    const amberGroupId = await getGroupIdByName(AMBER_GROUP.name);
    const apiUser = await addUser(testContext, ADMIN_USER, { user_email: API_USER.email, name: API_USER.email, password: API_USER.password, groups: [amberGroupId] });
    apiUserId = apiUser.id;
    const { plaintext_token } = await addUserTokenByAdmin(testContext, ADMIN_USER, apiUserId, { name: 'lockout-api', duration: TokenDuration.Days_30 });
    apiUserToken = plaintext_token;
    const platformAdminGroupId = await getGroupIdByName(PLATFORM_ADMIN_GROUP.name);
    const adminAccount = await addUser(testContext, ADMIN_USER, {
      user_email: ADMIN_ACCOUNT.email, name: ADMIN_ACCOUNT.email, password: ADMIN_ACCOUNT.password, groups: [platformAdminGroupId],
    });
    createdUserIds.push(externalUser.id, serviceAccount.id, apiUserId, adminAccount.id);
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

  describe('Below the max attempts', () => {
    it('should only count the failures, without any lock', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(2);
      expect(await getClientBase().exists(keysOf(LOCKOUT_USER.email).lock)).toEqual(0);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should count an unknown email exactly like a real account', async () => {
      await failLogin(UNKNOWN_EMAIL, 2);
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
    });

    it('should share the counter between email case variants', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email.toUpperCase(), WRONG_PASSWORD));
    });

    it('should not lift the lock of a concurrent failure when a right password is released', async () => {
      const emailHash = hashSHA256(normalizeEmail(UNKNOWN_EMAIL));
      const timings = { maxAttempts: 2, windowMs: 3600 * 1000, finalLockMs: LOCK_SECONDS * 1000, finalAction: 'temporary' as const };
      // A right password is counted, then a concurrent failure reaches the max attempts and locks
      const { windowId } = await redisRecordLocalAuthAttempt(emailHash, timings, 'right-password');
      const failure = await redisRecordLocalAuthAttempt(emailHash, timings, 'failure');
      expect(failure.isFinal).toBe(true);
      expect(failure.windowId).toEqual(windowId);
      // Releasing the right password undoes its own attempt only
      await redisReleaseLocalAuthAttempt(emailHash, { attemptToken: 'right-password', windowId });
      expect(await getClientBase().exists(keysOf(UNKNOWN_EMAIL).lock)).toEqual(1);
      expect(await failuresOf(UNKNOWN_EMAIL)).toEqual(1);
      // The attempt that set the lock lifts it
      await redisReleaseLocalAuthAttempt(emailHash, { attemptToken: 'failure', windowId });
      expect(await getClientBase().exists(keysOf(UNKNOWN_EMAIL).lock)).toEqual(0);
    });

    it('should not erase a failure of a later window when a right password is released', async () => {
      const emailHash = hashSHA256(normalizeEmail(UNKNOWN_EMAIL));
      const timings = { maxAttempts: 3, windowMs: 3600 * 1000, finalLockMs: LOCK_SECONDS * 1000, finalAction: 'temporary' as const };
      // A right password is counted, then its window expires (or is cleared) before it is released
      const rightPassword = await redisRecordLocalAuthAttempt(emailHash, timings, 'right-password');
      await expireWindow(UNKNOWN_EMAIL);
      // A concurrent failure starts a new window
      const failure = await redisRecordLocalAuthAttempt(emailHash, timings, 'failure');
      expect(failure.windowId).not.toEqual(rightPassword.windowId);
      // Releasing the right password must not erase the failure of the new window
      await redisReleaseLocalAuthAttempt(emailHash, { attemptToken: 'right-password', windowId: rightPassword.windowId });
      expect(await failuresOf(UNKNOWN_EMAIL)).toEqual(1);
    });

    it('should check no more passwords than the max attempts under concurrent attempts', async () => {
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      const attempts = Array.from({ length: 20 }, () => login(LOCKOUT_USER.email, WRONG_PASSWORD).catch((e) => e));
      const errors = await Promise.all(attempts);
      expect(compareSpy).toHaveBeenCalledTimes(3);
      expect(errors.filter((e) => e.extensions?.data?.lock === undefined)).toHaveLength(2);
      expect(errors.filter((e) => e.extensions?.data?.lock === 'temporary')).toHaveLength(18);
    });
  });

  describe('Final action: temporary', () => {
    it('should lock for the lockout duration once the max attempts are reached, without changing the account status', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD));
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password));
      expect(await accountStatusOf(LOCKOUT_USER.email)).toEqual('Active');
    });

    it('should lock for the lockout duration whatever the window', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_window: 5, local_auth_lockout_duration: 120 });
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD), 7200);
    });

    it('should reject the correct password during the lock without checking it', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password));
      expect(compareSpy).not.toHaveBeenCalled();
    });

    it('should neither count the attempts nor extend the lock during the lock', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      const failuresBefore = await failuresOf(LOCKOUT_USER.email);
      const remainingBefore = await lockRemainingMs(LOCKOUT_USER.email);
      for (let i = 0; i < 5; i += 1) {
        await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD));
      }
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(failuresBefore);
      expect(await lockRemainingMs(LOCKOUT_USER.email)).toBeLessThanOrEqual(remainingBefore);
    });

    it('should forget the failures when the lock is over', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      // The failures expire with the lock, not with the 60 min window
      const failuresRemainingMs = await getClientBase().pttl(keysOf(LOCKOUT_USER.email).failures);
      expect(failuresRemainingMs).toBeGreaterThan(0);
      expect(failuresRemainingMs).toBeLessThanOrEqual(LOCK_SECONDS * 1000);
      await expireLock(LOCKOUT_USER.email);
      await failLogin(LOCKOUT_USER.email, 2);
    });

    it('should allow the login again once the lock is over', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      await expireLock(LOCKOUT_USER.email);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should return the lock error through sessionLogin', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      await expectLocked(sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password));
    });
  });

  // The window is fixed: it starts on the first failure and is never extended
  describe('Failure window', () => {
    it('should start the counter again from zero when the window has expired', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await expireWindow(LOCKOUT_USER.email);
      await failLogin(LOCKOUT_USER.email, 2);
    });

    it('should not extend the window on the next failures', async () => {
      const { failures } = keysOf(LOCKOUT_USER.email);
      await failLogin(LOCKOUT_USER.email, 1);
      await shortenTtl(failures);
      await failLogin(LOCKOUT_USER.email, 1);
      await expectTtlNotExtended(failures);
    });

    it('should never forget the failures with a window of 0', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_window: 0 });
      await failLogin(LOCKOUT_USER.email, 2);
      // -1: the key exists without any TTL
      expect(await getClientBase().pttl(keysOf(LOCKOUT_USER.email).failures)).toEqual(-1);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD));
    });

    it('should give the attempts back once the temporary lock is over, with a window of 0', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_window: 0 });
      await reachMaxAttempts(LOCKOUT_USER.email);
      // The temporary lock gives the failures its own TTL, even without a window
      const failuresRemainingMs = await getClientBase().pttl(keysOf(LOCKOUT_USER.email).failures);
      expect(failuresRemainingMs).toBeGreaterThan(0);
      expect(failuresRemainingMs).toBeLessThanOrEqual(LOCK_SECONDS * 1000);
      await expireLock(LOCKOUT_USER.email);
      // All the max attempts again, not a lock on the next failure
      await failLogin(LOCKOUT_USER.email, 2);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD));
    });

    it('should still forget the failures of an unknown email after a day, with a window of 0', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_window: 0 });
      await failLogin(UNKNOWN_EMAIL, 1);
      const remainingMs = await getClientBase().pttl(keysOf(UNKNOWN_EMAIL).failures);
      expect(remainingMs).toBeGreaterThan(0);
      expect(remainingMs).toBeLessThanOrEqual(24 * 3600 * 1000);
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
      await reachMaxAttempts(LOCKOUT_USER.email);
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectPermanentlyLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password));
      expect(compareSpy).not.toHaveBeenCalled();
    });

    it('should stay locked when the lock is over', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      await expireLock(LOCKOUT_USER.email);
      await expect(login(LOCKOUT_USER.email, LOCKOUT_USER.password)).rejects.toBeDefined();
      expect(await accountStatusOf(LOCKOUT_USER.email)).toEqual('Locked');
    });

    it('should reject the API tokens of a locked account', async () => {
      await reachMaxAttempts(API_USER.email);
      try {
        const tokenUser = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: `Bearer ${apiUserToken}` }));
        expect(tokenUser).toBeUndefined();
      } finally {
        await userEditField(testContext, ADMIN_USER, apiUserId, [{ key: 'account_status', value: ['Active'] }]);
      }
    });

    it('should unlock the account when an administrator sets it back to Active', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      await userEditField(testContext, ADMIN_USER, lockoutUserId, [{ key: 'account_status', value: ['Active'] }]);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should report a permanent lock on an unknown email exactly like on a real account', async () => {
      await failLogin(UNKNOWN_EMAIL, 2);
      await expectPermanentlyLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
      await expectPermanentlyLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
    });

    it('should keep the permanent lock of an existing account until an administrator unlocks it', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      // -1: the lock never expires, so that no new attempt is ever given
      expect(await lockRemainingMs(LOCKOUT_USER.email)).toEqual(-1);
      await expectPermanentlyLocked(login(LOCKOUT_USER.email, LOCKOUT_USER.password));
    });

    it('should forget the permanent lock of an unknown email after a day', async () => {
      await reachMaxAttempts(UNKNOWN_EMAIL);
      const remainingMs = await lockRemainingMs(UNKNOWN_EMAIL);
      expect(remainingMs).toBeGreaterThan(0);
      expect(remainingMs).toBeLessThanOrEqual(24 * 3600 * 1000);
    });

    it('should keep the permanent lock of an external user until a login with another provider', async () => {
      const externalUser = await getUserByEmail(EXTERNAL_USER.email);
      await reachMaxAttempts(EXTERNAL_USER.email);
      expect(await lockRemainingMs(EXTERNAL_USER.email)).toEqual(-1);
      // The SSO login is never blocked, and clears the lock
      await sessionAuthenticateUser(testContext, buildRequest(), { id: externalUser!.id, internal_id: externalUser!.internal_id }, 'oidc');
      expect(await getClientBase().exists(keysOf(EXTERNAL_USER.email).lock)).toEqual(0);
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
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(0);
    });

    it('should reset the lockout on an SSO login', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      // OIDC, SAML, certificate and headers logins all end with a session login
      await sessionAuthenticateUser(testContext, buildRequest(), { id: lockoutUserId, internal_id: lockoutUserId }, 'oidc');
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(0);
    });

    it('should reset the lockout when an administrator sets the account back to Active', async () => {
      await reachMaxAttempts(LOCKOUT_USER.email);
      await userEditField(testContext, ADMIN_USER, lockoutUserId, [{ key: 'account_status', value: ['Active'] }]);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should not count the attempts from an IP that the IP whitelist blocks', async () => {
      enableIpWhitelist();
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expect(sessionLoginAs(LOCKOUT_USER.email, WRONG_PASSWORD)).rejects.toThrow(IP_NOT_ALLOWED);
      await expect(sessionLoginAs(UNKNOWN_EMAIL, WRONG_PASSWORD)).rejects.toThrow(IP_NOT_ALLOWED);
      await expect(authenticateUserByBasicAuth(testContext, buildRequest(), { username: API_USER.email, password: WRONG_PASSWORD })).rejects.toThrow(IP_NOT_ALLOWED);
      expect(compareSpy).not.toHaveBeenCalled();
      for (const email of [LOCKOUT_USER.email, UNKNOWN_EMAIL, API_USER.email]) {
        expect(await failuresOf(email)).toEqual(0);
      }
    });

    it('should count the attempts of a user excluded from the IP whitelist', async () => {
      enableIpWhitelist([lockoutUserId]);
      await expectBadCredentials(login(LOCKOUT_USER.email, WRONG_PASSWORD, '127.0.0.1'));
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(1);
      await expect(login(API_USER.email, WRONG_PASSWORD, '127.0.0.1')).rejects.toThrow(IP_NOT_ALLOWED);
    });

    it('should reset the lockout on a login accepted while the lockout is disabled', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_enabled: false });
      await sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password);
      // Enabling the lockout again does not bring back the previous failures
      await setLockoutPolicy(LOCKOUT_POLICY);
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(0);
    });

    it('should reset the lockout on a login accepted while the feature flag is disabled', async () => {
      await failLogin(LOCKOUT_USER.email, 2);
      const isFeatureEnabled = conf.isFeatureEnabled;
      vi.spyOn(conf, 'isFeatureEnabled').mockImplementation((flag: string) => (flag === conf.LOCAL_AUTH_LOCKOUT_FEATURE_FLAG ? false : isFeatureEnabled(flag)));
      await sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password);
      vi.restoreAllMocks();
      // Enabling the flag again does not bring back the previous failures
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(0);
    });

    it('should forget the failures of the previous email when it changes', async () => {
      const renamedEmail = 'lockout-renamed@opencti.io';
      await failLogin(LOCKOUT_USER.email, 2);
      try {
        await userEditField(testContext, ADMIN_USER, lockoutUserId, [{ key: 'user_email', value: [renamedEmail] }]);
        expect(await failuresOf(LOCKOUT_USER.email)).toEqual(0);
      } finally {
        await userEditField(testContext, ADMIN_USER, lockoutUserId, [{ key: 'user_email', value: [LOCKOUT_USER.email] }]);
      }
    });
  });

  // With the local auth disabled, the login form cannot log in with a password: its attempts must not lock
  // an account that logs in with another provider. Basic auth still checks the password, so it is still counted
  describe('Local auth disabled', () => {
    beforeEach(async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_final_action: 'permanent' });
      const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
      await updateLocalAuth(testContext, ADMIN_USER, settings.id, { enabled: false });
      resetCacheForEntity(ENTITY_TYPE_SETTINGS);
    });

    it('should neither count nor lock the login form attempts', async () => {
      for (let i = 0; i < 5; i += 1) {
        await expectBadCredentials(sessionLoginAs(LOCKOUT_USER.email, WRONG_PASSWORD));
      }
      await expectBadCredentials(sessionLoginAs(LOCKOUT_USER.email, LOCKOUT_USER.password));
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(0);
      expect(await accountStatusOf(LOCKOUT_USER.email)).toEqual('Active');
    });

    it('should still count the Basic auth failures', async () => {
      await expectBadCredentials(authenticateUserByBasicAuth(testContext, buildRequest(), { username: API_USER.email, password: WRONG_PASSWORD }));
      expect(await failuresOf(API_USER.email)).toEqual(1);
    });
  });

  describe('Inactive, expired and service accounts', () => {
    it.each([
      ['inactive', INACTIVE_USER.email, INACTIVE_USER.password],
      ['expired', EXPIRED_USER.email, EXPIRED_USER.password],
      ['service', SERVICE_ACCOUNT_EMAIL, 'any-password'],
    ])('should not check the password of an %s account, and count the attempt', async (_, email, password) => {
      const compareSpy = vi.spyOn(bcrypt, 'compareSync');
      await expectBadCredentials(login(email, password));
      expect(compareSpy).not.toHaveBeenCalled();
      expect(await failuresOf(email)).toEqual(1);
    });
  });

  // NIST SP 800-53 AC-7: administrative accounts reach the final action sooner than the other users
  describe('Administrative accounts', () => {
    beforeEach(async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_max_attempts: 5, local_auth_lockout_admin_max_attempts: 2 });
    });

    it('should apply the administrators threshold to an account with SETTINGS capabilities', async () => {
      await failLogin(ADMIN_ACCOUNT.email, 1);
      await expectLocked(login(ADMIN_ACCOUNT.email, WRONG_PASSWORD));
    });

    it('should apply the users threshold to the other accounts', async () => {
      await failLogin(LOCKOUT_USER.email, 4);
      await expectLocked(login(LOCKOUT_USER.email, WRONG_PASSWORD));
    });

    it('should apply the users threshold to an unknown email', async () => {
      await failLogin(UNKNOWN_EMAIL, 4);
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
    });

    it('should apply the administrators threshold to the failed MFA codes', async () => {
      const secret = totp.generateSecret();
      const adminAccount = await getUserByEmail(ADMIN_ACCOUNT.email);
      const mfaAdmin = { id: adminAccount?.id, user_email: ADMIN_ACCOUNT.email, otp_activated: true, otp_secret: secret } as AuthUser;
      const code = await totp.generate({ secret });
      const wrongCode = `${code.slice(0, 5)}${(Number(code[5]) + 1) % 10}`;
      const otpLogin = () => otpUserLogin({ session: { user: {}, save: () => {}, session_provider: 'local' } }, mfaAdmin, { code: wrongCode });
      await expectBadCredentials(otpLogin());
      await expectLocked(otpLogin());
    });
  });

  // The built-in admin is a break-glass account, used to unlock the other administrators
  describe('Built-in admin', () => {
    it('should never lock the built-in admin', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_final_action: 'permanent' });
      for (let i = 0; i < 5; i += 1) {
        await expectBadCredentials(login(API_EMAIL, WRONG_PASSWORD));
      }
      const user = await login(API_EMAIL, API_PASSWORD);
      expect(user.id).toEqual(ADMIN_USER.id);
      expect(await accountStatusOf(API_EMAIL)).toEqual('Active');
      expect(await getClientBase().exists(keysOf(API_EMAIL).failures, keysOf(API_EMAIL).lock)).toEqual(0);
    });

    it('should never count the failed MFA codes of the built-in admin', async () => {
      const secret = totp.generateSecret();
      const admin = { id: ADMIN_USER.id, user_email: API_EMAIL, otp_activated: true, otp_secret: secret } as AuthUser;
      const code = await totp.generate({ secret });
      const wrongCode = `${code.slice(0, 5)}${(Number(code[5]) + 1) % 10}`;
      for (let i = 0; i < 5; i += 1) {
        await expectBadCredentials(otpUserLogin({ session: { user: {}, save: () => {} } }, admin, { code: wrongCode }));
      }
      expect(await getClientBase().exists(keysOf(API_EMAIL).failures, keysOf(API_EMAIL).lock)).toEqual(0);
    });
  });

  describe('API access', () => {
    it('should count Basic auth failures and reject a locked account in Basic auth', async () => {
      const basicAuth = (password: string) => authenticateUserByBasicAuth(testContext, buildRequest(), { username: LOCKOUT_USER.email, password });
      await expectBadCredentials(basicAuth(WRONG_PASSWORD));
      await expectBadCredentials(basicAuth(WRONG_PASSWORD));
      await expectLocked(basicAuth(WRONG_PASSWORD));
      await expectLocked(basicAuth(LOCKOUT_USER.password));
    });

    it('should not count a right password without the Basic auth capability', async () => {
      await failLogin(LOCKOUT_USER.email, 1);
      await expect(authenticateUserByBasicAuth(testContext, buildRequest(), { username: LOCKOUT_USER.email, password: LOCKOUT_USER.password }))
        .rejects.toThrow('You are not allowed to use API basic auth');
      expect(await failuresOf(LOCKOUT_USER.email)).toEqual(1);
    });

    it('should reset the failure counter on a successful Basic auth', async () => {
      await failLogin(API_USER.email, 2);
      const user = await authenticateUserByBasicAuth(testContext, buildRequest(), { username: API_USER.email, password: API_USER.password });
      expect(user.id).toEqual(apiUserId);
      expect(await failuresOf(API_USER.email)).toEqual(0);
    });

    it('should keep API tokens and open sessions working during a temporary lock', async () => {
      const basicHeader = `Basic ${Buffer.from(`${API_USER.email}:${API_USER.password}`).toString('base64')}`;
      // Sanity check: Basic auth works before the lock
      const beforeLock = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: basicHeader }));
      expect(beforeLock?.id).toEqual(apiUserId);
      // Lock the user
      await reachMaxAttempts(API_USER.email);
      // Basic auth is blocked
      const basicUser = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: basicHeader }));
      expect(basicUser).toBeUndefined();
      // Bearer API token still works
      const tokenUser = await authenticateUserFromRequest(testContext, buildApiRequest({ authorization: `Bearer ${apiUserToken}` }));
      expect(tokenUser?.id).toEqual(apiUserId);
      // Open session still works
      const sessionUser = await authenticateUserFromRequest(testContext, buildApiRequest({}, { user: { id: apiUserId } }));
      expect(sessionUser?.id).toEqual(apiUserId);
    });
  });

  // Failed MFA codes count like failed passwords, so that the second factor cannot be brute-forced
  describe('MFA', () => {
    const mfaUser = () => ({ id: mfaUserId, user_email: MFA_USER.email, otp_activated: true, otp_secret: mfaSecret }) as AuthUser;
    // The session of a local password login, waiting for its MFA code
    const otpLogin = (code: string, provider = 'local') => otpUserLogin({ session: { user: {}, save: () => {}, session_provider: provider } }, mfaUser(), { code });
    const validCode = () => totp.generate({ secret: mfaSecret });
    // Any other 6 digits code than the valid one
    const wrongCode = async () => {
      const code = await validCode();
      return `${code.slice(0, 5)}${(Number(code[5]) + 1) % 10}`;
    };

    it('should count a failed MFA code like a failed password', async () => {
      await expectBadCredentials(otpLogin(await wrongCode()));
      await failLogin(MFA_USER.email, 1);
      await expectLocked(login(MFA_USER.email, WRONG_PASSWORD));
    });

    it('should reject a valid MFA code during a lock', async () => {
      await expectBadCredentials(otpLogin(await wrongCode()));
      await expectBadCredentials(otpLogin(await wrongCode()));
      await expectLocked(otpLogin(await wrongCode()));
      await expectLocked(otpLogin(await validCode()));
    });

    it('should never block a valid MFA code after another provider, but count the failed ones', async () => {
      await reachMaxAttempts(MFA_USER.email);
      // LDAP and SSO logins are never blocked by the local lock, their MFA code neither
      expect(await otpLogin(await validCode(), 'oidc')).toBe(true);
      expect(await failuresOf(MFA_USER.email)).toEqual(0);
      await expectBadCredentials(otpLogin(await wrongCode(), 'oidc'));
      expect(await failuresOf(MFA_USER.email)).toEqual(1);
    });

    it('should reset the counter after a valid MFA code', async () => {
      await expectBadCredentials(otpLogin(await wrongCode()));
      await expectBadCredentials(otpLogin(await wrongCode()));
      expect(await otpLogin(await validCode())).toBe(true);
      expect(await failuresOf(MFA_USER.email)).toEqual(0);
    });

    it('should not reset the counter on a right password alone', async () => {
      await expectBadCredentials(otpLogin(await wrongCode()));
      // The right password undoes its own attempt, but keeps the failure of the MFA code
      await sessionLoginAs(MFA_USER.email, MFA_USER.password);
      expect(await failuresOf(MFA_USER.email)).toEqual(1);
      await expectBadCredentials(otpLogin(await wrongCode()));
      await expectLocked(otpLogin(await wrongCode()));
    });

    it('should lift the lock of a right password reaching the max attempts, but keep the failures', async () => {
      await expectBadCredentials(otpLogin(await wrongCode()));
      await expectBadCredentials(otpLogin(await wrongCode()));
      // The third attempt reaches the max attempts, but its password is right: it waits for its MFA code
      await sessionLoginAs(MFA_USER.email, MFA_USER.password);
      expect(await getClientBase().exists(keysOf(MFA_USER.email).lock)).toEqual(0);
      expect(await failuresOf(MFA_USER.email)).toEqual(2);
      await expectLocked(otpLogin(await wrongCode()));
    });

    it('should set the account to Locked with the permanent final action', async () => {
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_final_action: 'permanent' });
      try {
        await expectBadCredentials(otpLogin(await wrongCode()));
        await expectBadCredentials(otpLogin(await wrongCode()));
        await expectPermanentlyLocked(otpLogin(await wrongCode()));
        expect(await accountStatusOf(MFA_USER.email)).toEqual('Locked');
      } finally {
        await userEditField(testContext, ADMIN_USER, mfaUserId, [{ key: 'account_status', value: ['Active'] }]);
      }
    });

    it('should count a failed MFA code in the forgotten password flow', async () => {
      const transactionId = uuid();
      await redisSetForgotPasswordOtp(transactionId, { email: MFA_USER.email, hashedOtp: bcrypt.hashSync('12345678'), mfa_activated: true, mfa_validated: false, userId: mfaUserId });
      await expectBadCredentials(verifyMfa(testContext, { transactionId, code: await wrongCode() }));
      await expectBadCredentials(verifyMfa(testContext, { transactionId, code: await wrongCode() }));
      await expectLocked(verifyMfa(testContext, { transactionId, code: await wrongCode() }));
      await expectLocked(verifyMfa(testContext, { transactionId, code: await validCode() }));
      await expireLock(MFA_USER.email);
      expect(await verifyMfa(testContext, { transactionId, code: await validCode() })).toBe(true);
    });

    it('should reset the counter after a valid MFA code while the lockout is disabled', async () => {
      await expectBadCredentials(otpLogin(await wrongCode()));
      await expectBadCredentials(otpLogin(await wrongCode()));
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_enabled: false });
      expect(await otpLogin(await validCode())).toBe(true);
      // Enabling the lockout again does not bring back the previous failures
      await setLockoutPolicy(LOCKOUT_POLICY);
      expect(await failuresOf(MFA_USER.email)).toEqual(0);
    });

    it('should reset the counter after a valid MFA code in the forgotten password flow while the lockout is disabled', async () => {
      const transactionId = uuid();
      await redisSetForgotPasswordOtp(transactionId, { email: MFA_USER.email, hashedOtp: bcrypt.hashSync('12345678'), mfa_activated: true, mfa_validated: false, userId: mfaUserId });
      await expectBadCredentials(verifyMfa(testContext, { transactionId, code: await wrongCode() }));
      await setLockoutPolicy({ ...LOCKOUT_POLICY, local_auth_lockout_enabled: false });
      expect(await verifyMfa(testContext, { transactionId, code: await validCode() })).toBe(true);
      await setLockoutPolicy(LOCKOUT_POLICY);
      expect(await failuresOf(MFA_USER.email)).toEqual(0);
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
      await reachMaxAttempts(LOCKOUT_USER.email);
      // The LDAP login is never blocked by the local lock
      await sessionLogin(buildSessionContext(), { email: LOCKOUT_USER.email, password: 'ldap-password' });
      // Any successful login deletes every key for this email
      expect(await getClientBase().exists(keysOf(LOCKOUT_USER.email).lock)).toEqual(0);
      const user = await login(LOCKOUT_USER.email, LOCKOUT_USER.password);
      expect(user.user_email).toEqual(LOCKOUT_USER.email);
    });

    it('should return the generic error instead of the local lock when another form provider exists', async () => {
      // The fake LDAP rejects this email, as LDAP would reject a wrong password
      for (let i = 0; i < 3; i += 1) {
        await expectBadCredentials(sessionLoginAs(UNKNOWN_EMAIL, WRONG_PASSWORD));
      }
      // The local lock exists, it is just not shown
      await expectLocked(login(UNKNOWN_EMAIL, WRONG_PASSWORD));
    });
  });
});
