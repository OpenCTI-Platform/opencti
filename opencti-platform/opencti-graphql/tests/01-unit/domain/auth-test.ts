import { describe, expect, it } from 'vitest';
import { generateOtp } from '../../../src/modules/auth/auth-domain';

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
