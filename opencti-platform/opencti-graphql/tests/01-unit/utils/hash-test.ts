import { describe, expect, it } from 'vitest';
import { compareHashSHA256, hashSHA256 } from '../../../src/utils/hash';

describe('Hash utilities: compareHashSHA256', () => {
  // Ref text.
  const CONTENT_1 = `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt 
  ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut 
  aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore 
  eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt 
  mollit anim id est laborum.`;

  // Ref text + a sentence at the end.
  const CONTENT_2 = `Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt 
  ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut 
  aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore 
  eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt 
  mollit anim id est laborum. Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium.`;

  // Ref text changing second work.
  const CONTENT_3 = `Lorem ipsomme dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt 
  ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut 
  aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore 
  eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt 
  mollit anim id est laborum.`;

  it('should return true if same content', () => {
    const hash1 = hashSHA256(CONTENT_1);
    const hash2 = hashSHA256(CONTENT_2);
    expect(compareHashSHA256(CONTENT_1, hash1)).toEqual(true);
    expect(compareHashSHA256(CONTENT_2, hash2)).toEqual(true);
  });

  it('should return false if not same content', () => {
    const hash = hashSHA256(CONTENT_1);
    expect(compareHashSHA256('an other content', hash)).toEqual(false);
  });

  it('should return false if content differs at the end', () => {
    const hash = hashSHA256(CONTENT_1);
    expect(compareHashSHA256(CONTENT_2, hash)).toEqual(false);
  });

  it('should return false if content differs at start', () => {
    const hash = hashSHA256(CONTENT_1);
    expect(compareHashSHA256(CONTENT_3, hash)).toEqual(false);
  });
});
