import { describe, it, expect } from 'vitest';
import { isRelativeUrl } from './url';

describe('isRelativeUrl', () => {
  describe('relative URLs (should return true)', () => {
    it('should return true for an absolute path', () => {
      expect(isRelativeUrl('/dashboard/profile')).toBe(true);
    });

    it('should return true for a relative path with directory traversal', () => {
      expect(isRelativeUrl('../settings')).toBe(true);
    });

    it('should return true for a relative path without leading slash', () => {
      expect(isRelativeUrl('page/sub')).toBe(true);
    });

    it('should return true for a path with query string', () => {
      expect(isRelativeUrl('/search?q=test')).toBe(true);
    });

    it('should return true for a path with fragment', () => {
      expect(isRelativeUrl('/home#section')).toBe(true);
    });
  });

  describe('absolute and invalid URLs (should return false)', () => {
    it('should return false for an https URL', () => {
      expect(isRelativeUrl('https://example.com')).toBe(false);
    });

    it('should return false for an http URL', () => {
      expect(isRelativeUrl('http://example.com/path')).toBe(false);
    });

    it('should return false for a protocol-relative URL', () => {
      expect(isRelativeUrl('//example.com/path')).toBe(false);
    });

    it('should return false for a javascript: URL', () => {
      expect(isRelativeUrl('javascript:alert(1)')).toBe(false);
    });

    it('should return false for a data: URL', () => {
      expect(isRelativeUrl('data:text/html,<h1>hi</h1>')).toBe(false);
    });

    it('should return false for a ftp: URL', () => {
      expect(isRelativeUrl('ftp://files.example.com')).toBe(false);
    });

    it('should return false for an empty string', () => {
      expect(isRelativeUrl('')).toBe(false);
    });

    it('should return false for an encoded scheme (javas%63ript:)', () => {
      expect(isRelativeUrl('javas%63ript:alert(1)')).toBe(false);
    });

    it('should return false for an encoded scheme with uppercase hex (%43)', () => {
      expect(isRelativeUrl('javas%43ript:alert(1)')).toBe(false);
    });

    it('should return false for a fully encoded scheme (http%3A//evil.com)', () => {
      expect(isRelativeUrl('http%3A//evil.com')).toBe(false);
    });

    it('should return false for a backslash-based path (\\\\example.com)', () => {
      expect(isRelativeUrl('\\\\example.com')).toBe(false);
    });

    it('should return false for a single backslash path (\\example.com)', () => {
      expect(isRelativeUrl('\\example.com')).toBe(false);
    });

    it('should return false for a value with only whitespace', () => {
      expect(isRelativeUrl('   ')).toBe(false);
    });
  });

  describe('whitespace handling (should return true after trim)', () => {
    it('should return true for a relative URL with leading spaces', () => {
      expect(isRelativeUrl('  /dashboard')).toBe(true);
    });

    it('should return true for a relative URL with trailing spaces', () => {
      expect(isRelativeUrl('/dashboard  ')).toBe(true);
    });
  });
});
