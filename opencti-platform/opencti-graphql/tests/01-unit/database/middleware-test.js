import { hashMergeValidation } from '../../../src/database/middleware';

test('should hashes allowed to merge', () => {
  const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
  const instanceTwo = { hashes: { MD5: 'md5' } };
  hashMergeValidation([instanceOne, instanceTwo]);
});

test('should hashes have collisions', () => {
  const instanceOne = { hashes: { MD5: 'md5instanceOne' } };
  const instanceTwo = { hashes: { MD5: 'md5instanceTwo' } };
  const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
  expect(merge).toThrow();
});

test('should hashes have complex collisions', () => {
  const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
  const instanceTwo = { hashes: { MD5: 'md5', 'SHA-1': 'SHA2' } };
  const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
  expect(merge).toThrow();
});
