import { describe, expect, it } from 'vitest';
import { normalizeEmail } from '../../../src/utils/email';

describe('Email normalization tests', () => {
  it('should lowercase mixed case emails', () => {
    expect(normalizeEmail('Admin@Corp.com')).toBe('admin@corp.com');
  });

  it('should trim a leading space', () => {
    expect(normalizeEmail(' admin@corp.com')).toBe('admin@corp.com');
  });

  it('should trim a trailing space', () => {
    expect(normalizeEmail('admin@corp.com ')).toBe('admin@corp.com');
  });

  it('should trim surrounding spaces combined with mixed case', () => {
    expect(normalizeEmail(' ADMIN@CORP.COM ')).toBe('admin@corp.com');
  });

  it('should trim leading and trailing tabs', () => {
    expect(normalizeEmail('\tadmin@corp.com\t')).toBe('admin@corp.com');
  });

  it('should trim surrounding NBSP (non-breaking space, U+00A0)', () => {
    expect(normalizeEmail('\u00A0admin@corp.com\u00A0')).toBe('admin@corp.com');
  });

  it('should NOT strip zero-width spaces (U+200B), matching schema/identifier.js trim() behavior', () => {
    expect(normalizeEmail('\u200Badmin@corp.com\u200B')).toBe('\u200Badmin@corp.com\u200B');
  });

  it('should preserve +tag suffixes as distinct addresses', () => {
    expect(normalizeEmail('user+tag@corp.com')).toBe('user+tag@corp.com');
    expect(normalizeEmail('user+tag@corp.com')).not.toBe(normalizeEmail('user@corp.com'));
  });

  it('should resolve all space/case variants of the same email to one canonical value', () => {
    const variants = [
      'Admin@Corp.com',
      ' admin@corp.com',
      'admin@corp.com ',
      ' ADMIN@CORP.COM ',
      '\tadmin@corp.com\t',
      '\u00A0admin@corp.com\u00A0',
    ];
    const normalized = variants.map((v) => normalizeEmail(v));
    expect(new Set(normalized).size).toBe(1);
    expect(normalized[0]).toBe('admin@corp.com');
  });
});
