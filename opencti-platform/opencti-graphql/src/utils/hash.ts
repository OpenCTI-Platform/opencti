import * as crypto from 'crypto';
import { getPlatformCrypto } from './platformCrypto';

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

/**
 * Hash a token using hmac algorithm.
 * @param token the token to hash
 */
let hmacDerivationPromise: Promise<{ hmac: (data: string) => string }>;
const TOKEN_DERIVATION_PATH = ['authentication', 'token'];
export const generateTokenHmac = async (token: string): Promise<string> => {
  const factory = await getPlatformCrypto();
  if (!hmacDerivationPromise) {
    hmacDerivationPromise = factory.deriveHmac(TOKEN_DERIVATION_PATH, 1);
  }
  const hmacDerivation = await hmacDerivationPromise;
  return hmacDerivation.hmac(token);
};
