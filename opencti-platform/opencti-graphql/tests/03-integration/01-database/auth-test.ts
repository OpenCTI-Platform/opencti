import { describe, expect, it } from 'vitest';
import { askSendOtp, getLocalProviderUser } from '../../../src/modules/auth/auth-domain';
import { testContext } from '../../utils/testQuery';
import { validate as uuidValidate } from 'uuid';
import { OTP_TTL, redisGetForgotPasswordOtp } from '../../../src/database/redis';

describe('getLocalProviderUser', () => {
  it('Should be able to return a user with an email', async () => {
    const user = await getLocalProviderUser('anais@opencti.io');
    expect(user.user_email).toEqual('anais@opencti.io');
    expect(user.name).toEqual('anais@opencti.io');
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