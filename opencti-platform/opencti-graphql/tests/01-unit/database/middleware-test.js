import { describe, expect, it } from 'vitest';
import { hashMergeValidation } from '../../../src/database/middleware';

describe('middleware', () => {
  it('should hashes allowed to merge', () => {
    const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
    const instanceTwo = { hashes: { MD5: 'md5' } };
    hashMergeValidation([instanceOne, instanceTwo]);
  });

  it('should hashes have collisions', () => {
    const instanceOne = { hashes: { MD5: 'md5instanceOne' } };
    const instanceTwo = { hashes: { MD5: 'md5instanceTwo' } };
    const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
    expect(merge).toThrow();
  });

  it('should hashes have complex collisions', () => {
    const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
    const instanceTwo = { hashes: { MD5: 'md5', 'SHA-1': 'SHA2' } };
    const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
    expect(merge).toThrow();
  });
});
