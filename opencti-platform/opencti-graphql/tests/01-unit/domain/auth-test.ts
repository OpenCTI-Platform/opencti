import { describe, expect, it } from 'vitest';
import { validate as uuidValidate } from 'uuid';
import { askSendOtp, generateOtp, getLocalProviderUser } from '../../../src/modules/auth/auth-domain';
import { testContext } from '../../utils/testQuery';
import { OTP_TTL, redisGetForgotPasswordOtp } from '../../../src/database/redis';

describe('getLocalProviderUser', () => {
  it('Should be able to return a user with an email', async () => {
    const user = await getLocalProviderUser('anais@opencti.io');
    expect(user.user_email).toEqual('anais@opencti.io');
  });
  it('Should be able to return a user with a name', async () => {
    const user = await getLocalProviderUser('anais@opencti.io');
    expect(user.name).toEqual('anais@opencti.io');
  });
  it('Should throw an error if no user founded', async () => {
    expect(async () => getLocalProviderUser('noResul@opencti.io')).rejects.toThrow('User not found');
  });
  it('Should throw an error if user is external', async () => {
    // admin is external
    expect(async () => getLocalProviderUser('admin@opencti.io')).rejects.toThrow('External user');
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
