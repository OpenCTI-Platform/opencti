import { describe, expect, it } from 'vitest';
import { isCompatibleVersionWithMinimal } from '../../../src/utils/version';
import { normalizeBuildCommit } from '../../../src/utils/build-info';

describe('Version utils Tests', () => {
  it('should test compatible version with minimal', () => {
    expect(isCompatibleVersionWithMinimal('6.0.0', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.12.16', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.12.17', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.13.1', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.11.16', '5.12.16')).toBeFalsy();
    expect(isCompatibleVersionWithMinimal('5.12.15', '5.12.16')).toBeFalsy();
    expect(isCompatibleVersionWithMinimal('5.0.0', '5.12.16')).toBeFalsy();
    expect(isCompatibleVersionWithMinimal('4.12.16', '5.12.16')).toBeFalsy();
  });

  describe('Build commit normalization', () => {
    it('should shorten a full commit hash', () => {
      expect(normalizeBuildCommit('0123456789abcdef0123456789abcdef01234567')).toBe('0123456');
    });

    it('should preserve a seven-character commit hash', () => {
      expect(normalizeBuildCommit('abcdef0')).toBe('abcdef0');
    });

    it('should trim surrounding whitespace', () => {
      expect(normalizeBuildCommit('  abcdef012345  ')).toBe('abcdef0');
    });

    it.each([undefined, '', '   '])('should reject a missing or blank commit hash', (value) => {
      expect(normalizeBuildCommit(value)).toBeUndefined();
    });

    it.each(['not-a-commit', '123456', 'abcdefg'])('should reject a malformed commit hash', (value) => {
      expect(normalizeBuildCommit(value)).toBeUndefined();
    });
  });
});
