import * as crypto from 'crypto';

/**
 * Hash a string using SHA-256 algorithm.
 * @param input The string to hash.
 * @returns The hash.
 */
export const hashSHA256 = (input: string) => {
  return crypto.createHash('sha256').update(input).digest('hex');
};

/**
 * Compare a string with a hash SHA-256.
 * @param input The string to compare.
 * @param hash The hash to use as reference.
 * @returns True if the string matches the hash.
 */
export const compareHashSHA256 = (input: string, hash: string) => {
  return hashSHA256(input) === hash;
};
