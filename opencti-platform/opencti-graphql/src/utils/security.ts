import * as crypto from 'crypto';
import { hashSHA256 } from './hash';

export interface GeneratedToken {
  token: string;
  hash: string;
  masked_token: string;
}

/**
 * Generate a secure random token.
 * 48 bytes = 384 bits of entropy.
 * Returns the plain token (to be shown once), the hash (to be stored), and a masked version.
 */
export const generateSecureToken = (): GeneratedToken => {
  // 48 bytes -> base64 -> 64 chars
  const random = crypto.randomBytes(48).toString('base64url');
  const token = `flgrn_octi_tkn_${random}`;
  const hash = hashSHA256(token);
  const masked_token = `****${token.slice(-4)}`;

  return {
    token,
    hash,
    masked_token,
  };
};
