import { describe, it, expect } from 'vitest';
import { askSendOtp, generateOtp, getUser, verifyOtp } from '../../../src/modules/auth/auth-domain';
import { AuthenticationFailure } from '../../../src/config/errors';
import { testContext } from '../../utils/testQuery';
import { validate as uuidValidate } from 'uuid';
import { OTP_TTL, redisGetForgotPasswordOtp } from '../../../src/database/redis';

describe('getUser', () => {
  it('Should be able to return a user with an email', async () => {
    const user = await getUser('anais@opencti.io');
    expect(user.user_email).toEqual('anais@opencti.io');
  });
  it('Should be able to return a user with a name', async () => {
    const user = await getUser('anais@opencti.io');
    expect(user.name).toEqual('anais@opencti.io');
  });
  it('Should throw an error if no user founded', async () => {
    expect(async () => await getUser('noResul@opencti.io')).rejects.toThrow(AuthenticationFailure());
  });
  it('Should throw an error if user is external', async () => {
    // admin is external
    expect(async () => await getUser('admin@opencti.io')).rejects.toThrow('External user');
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

let transactionId: string;
describe('askSendOtp', () => {
  it('Should return an uuid with an existed user', async () => {
    transactionId = await askSendOtp(testContext, { email: 'anais@opencti.io' });
    expect(uuidValidate(transactionId)).toBeTruthy();
  });
  it('Should find redis key', async () => {
    const key = await redisGetForgotPasswordOtp(transactionId);
    expect(key).toBeTruthy();
    expect(key.hashedOtp).toBeTypeOf('string');
    expect(key.email).toBe('anais@opencti.io');
    expect(key.otp_activated).toBeFalsy();
    expect(key.otp_validated).toBeFalsy();
    expect(key.ttl).toBeLessThanOrEqual(OTP_TTL);
  });
  it('Should return an uuid with an wrong email', async () => {
    const result = await askSendOtp(testContext, { email: 'noResul@opencti.io' });
    expect(uuidValidate(result)).toBeTruthy();
  });
});
