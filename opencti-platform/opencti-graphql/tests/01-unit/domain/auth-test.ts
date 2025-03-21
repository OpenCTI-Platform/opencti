import { describe, it, expect } from 'vitest';
import { askResetPassword, generateCode, getUser } from '../../../src/modules/auth/auth-domain';
import { AuthenticationFailure } from '../../../src/config/errors';

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

describe('generateCode', () => {
  it('Should return a 8 char code', async () => {
    const result = generateCode();
    expect(result.length).toEqual(8);
  });
  it('Should dont have alphabetic char', async () => {
    const result = parseInt(generateCode());
    expect(result).not.toBeNaN();
  });
});

describe('askResetPassword', () => {
  it('Should return true with an existed user', () => {
    const result = askResetPassword('anais@opencti.io');
    expect(result).toBeTruthy();
  });
  it('Should return true with an wrong email', () => {
    const result = askResetPassword('noResul@opencti.io');
    expect(result).toBeTruthy();
  });
});
