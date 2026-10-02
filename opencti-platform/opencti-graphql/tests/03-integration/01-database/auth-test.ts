import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import bcrypt from 'bcryptjs';
import { askSendOtp, changePassword, generateOtp, getLocalProviderUser } from '../../../src/modules/auth/auth-domain';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { v4 as uuid, validate as uuidValidate } from 'uuid';
import { OTP_TTL, redisGetForgotPasswordOtp, redisSetForgotPasswordOtp } from '../../../src/database/redis';
import { addUser, userDelete } from '../../../src/modules/user/user-domain';
import { getSettingsFromDatabase } from '../../../src/domain/settings';
import { updateLocalAuth } from '../../../src/domain/setting-auth';
import type { BasicStoreSettings } from '../../../src/types/settings';

describe('getLocalProviderUser', () => {
  it('Should be able to return a user with an email', async () => {
    const user = await getLocalProviderUser('anais@opencti.io');
    expect(user.user_email).toEqual('anais@opencti.io');
    expect(user.name).toEqual('anais@opencti.io');
  });
});

describe('generateOtp', () => {
  it('Should return a 8 char code', async () => {
    const result = generateOtp();
    expect(result.length).toEqual(8);
  });
  it('Should dont have alphabetic char', async () => {
    const result = parseInt(generateOtp());
    expect(result).not.toBeNaN();
  });
});

describe('askSendOtp', () => {
  let transactionId: string;
  it('Should return an uuid with an existed user', async () => {
    transactionId = await askSendOtp(testContext, { email: 'anais@opencti.io' });
    expect(uuidValidate(transactionId)).toBeTruthy();
  });
  it('Should find redis key', async () => {
    const key = await redisGetForgotPasswordOtp(transactionId);
    expect(key).toBeTruthy();
    expect(key.hashedOtp).toBeTypeOf('string');
    expect(key.email).toBe('anais@opencti.io');
    expect(key.mfa_activated).toBeFalsy();
    expect(key.mfa_validated).toBeFalsy();
    expect(key.ttl).toBeLessThanOrEqual(OTP_TTL);
  });
  it('Should return an uuid with an wrong email', async () => {
    const result = await askSendOtp(testContext, { email: 'noResul@opencti.io' });
    expect(uuidValidate(result)).toBeTruthy();
  });
});

describe('changePassword with password history', () => {
  const email = 'reset_password_history@opencti.io';
  const otp = '12345678';
  let settings: BasicStoreSettings;
  let userId: string;

  const setHistoryCount = (count: number) => updateLocalAuth(testContext, ADMIN_USER, settings.id, {
    enabled: true,
    password_policy_max_length: 0,
    password_policy_min_length: 0,
    password_policy_min_lowercase: 0,
    password_policy_min_numbers: 0,
    password_policy_min_symbols: 0,
    password_policy_min_uppercase: 0,
    password_policy_min_words: 0,
    password_policy_validity_days: 0,
    password_policy_history_count: count,
  });

  // The transaction askSendOtp would create, with a code known to the test
  const startReset = async () => {
    const transactionId = uuid();
    await redisSetForgotPasswordOtp(transactionId, { hashedOtp: bcrypt.hashSync(otp), email, mfa_activated: false, mfa_validated: false, userId });
    return transactionId;
  };

  beforeAll(async () => {
    settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    const user = await addUser(testContext, ADMIN_USER, { name: 'Reset password history', user_email: email, password: 'Reset-History-1!' } as any);
    userId = user.id;
    await setHistoryCount(2);
  });

  afterAll(async () => {
    await setHistoryCount(0);
    await userDelete(testContext, ADMIN_USER, userId);
  });

  it('Should refuse a reused password with PASSWORD_REUSED and keep the transaction for a retry', async () => {
    const transactionId = await startReset();
    await expect(changePassword(testContext, { transactionId, otp, newPassword: 'Reset-History-1!' }))
      .rejects.toMatchObject({ extensions: { code: 'PASSWORD_REUSED' } });
    const key = await redisGetForgotPasswordOtp(transactionId);
    expect(key.hashedOtp).toBeTypeOf('string');
    // Same transaction and code, a new password: the change goes through
    expect(await changePassword(testContext, { transactionId, otp, newPassword: 'Reset-History-2!' })).toBe(true);
  });

  it('Should report an expired code with its own code, which the screen explains', async () => {
    await expect(changePassword(testContext, { transactionId: uuid(), otp, newPassword: 'Reset-History-3!' }))
      .rejects.toMatchObject({
        message: 'Password reset code expired or not found. Please request a new one.',
        extensions: { code: 'PASSWORD_RESET_EXPIRED' },
      });
  });
});
