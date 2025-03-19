import { describe, it, expect } from 'vitest';
import { askResetPassword, generateCode, getEmail } from '../../../src/modules/auth/auth-domain';
import { AuthenticationFailure } from '../../../src/config/errors';

describe('getEmail', () => {
  it('Should be able to return user email', async () => {
    const result = await getEmail('anais@opencti.io');
    expect(result).toEqual('anais@opencti.io');
  });
  it('Should throw an error if no user founded', async () => {
    expect(async () => await getEmail('noResul@opencti.io')).rejects.toThrow(AuthenticationFailure());
  });
  it('Should throw an error if user is external', async () => {
    // admin is external
    expect(async () => await getEmail('admin@opencti.io')).rejects.toThrow('External user');
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
  it('Should return true', () => {
    const result = askResetPassword('francois.grunert@filigran.io');
    expect(result).toBeTruthy();
  });
});
