import { describe, it, expect } from 'vitest';
import { isSyntaxOrParsingError, isFileAccessError, generateFileUploadErrorMessage, hasEncodedSpecialChars, sanitizeFileName } from '../../../src/domain/file-error-helpers';
import { isValidStixBundle, generateBundleValidationErrorMessage } from '../../../src/domain/stix-validation-helpers';

interface ErrorWithCode extends Error {
  code?: string;
}

describe('File Error Helpers', () => {
  describe('isSyntaxOrParsingError', () => {
    it('should identify SyntaxError', () => {
      const error = new SyntaxError('Unexpected token');
      expect(isSyntaxOrParsingError(error)).toBe(true);
    });

    it('should identify JSON parse errors', () => {
      const error = new Error('Unexpected token < in JSON at position 0');
      expect(isSyntaxOrParsingError(error)).toBe(true);
    });

    it('should not identify regular errors', () => {
      const error = new Error('File not found');
      expect(isSyntaxOrParsingError(error)).toBe(false);
    });
  });

  describe('isFileAccessError', () => {
    it('should identify ENOENT errors', () => {
      const error: ErrorWithCode = new Error('File not found');
      error.code = 'ENOENT';
      expect(isFileAccessError(error)).toBe(true);
    });

    it('should identify S3 NoSuchKey errors', () => {
      const error: ErrorWithCode = new Error('The specified key does not exist');
      error.code = 'NoSuchKey';
      expect(isFileAccessError(error)).toBe(true);
    });

    it('should identify errors by message when code is missing', () => {
      const error = new Error('ENOENT: no such file or directory');
      expect(isFileAccessError(error)).toBe(true);
    });

    it('should not identify other errors', () => {
      const error = new Error('Permission denied');
      expect(isFileAccessError(error)).toBe(false);
    });
  });

  describe('hasEncodedSpecialChars', () => {
    it('should detect URL-encoded characters', () => {
      expect(hasEncodedSpecialChars('file%20name.json')).toBe(true);
      expect(hasEncodedSpecialChars('file%22name.json')).toBe(true);
      expect(hasEncodedSpecialChars('file%3Cname.json')).toBe(true);
    });

    it('should not flag normal filenames', () => {
      expect(hasEncodedSpecialChars('normal-file-name.json')).toBe(false);
      expect(hasEncodedSpecialChars('file_name.json')).toBe(false);
    });
  });

  describe('sanitizeFileName', () => {
    it('should decode and sanitize problematic characters', () => {
      expect(sanitizeFileName('test%22file.json')).toBe('test-file.json');
      expect(sanitizeFileName('test%3Cfile.json')).toBe('test_file.json');
      expect(sanitizeFileName('test%20file.json')).toBe('test file.json');
    });

    it('should leave normal filenames unchanged', () => {
      expect(sanitizeFileName('normal-file.json')).toBe('normal-file.json');
    });

    it('should handle malformed encoding gracefully', () => {
      const malformed = 'test%ZZfile.json';
      expect(sanitizeFileName(malformed)).toBe(malformed);
    });
  });

  describe('generateFileUploadErrorMessage', () => {
    it('should generate error for file access with encoded chars', () => {
      const error: ErrorWithCode = new Error('File not found');
      error.code = 'ENOENT';
      const fileName = 'test%22file.json';

      const result = generateFileUploadErrorMessage(error, fileName);
      
      expect(result.message).toContain('Unable to access the file');
      expect(result.message).toContain('special characters');
      expect(result.data?.originalFileName).toBe('test%22file.json');
      expect(result.data?.suggestedFileName).toBe('test-file.json');
    });

    it('should generate error for file access without encoded chars', () => {
      const error: ErrorWithCode = new Error('File not found');
      error.code = 'ENOENT';
      const fileName = 'normalfile.json';

      const result = generateFileUploadErrorMessage(error, fileName);
      
      expect(result.message).toContain('Unable to access the file');
      expect(result.message).toContain('may not exist');
      expect(result.data).toBeUndefined();
    });

    it('should generate error for syntax issues', () => {
      const error = new SyntaxError('Unexpected token');
      const fileName = 'test.json';

      const result = generateFileUploadErrorMessage(error, fileName);
      
      expect(result.message).toContain('Invalid JSON format');
      expect(result.message).toContain('test.json');
    });

    it('should generate generic error for unknown errors', () => {
      const error = new Error('Unknown error');
      const fileName = 'test.json';

      const result = generateFileUploadErrorMessage(error, fileName);
      
      expect(result.message).toContain('Error processing file');
      expect(result.message).toContain('Unknown error');
    });
  });
});

describe('STIX Validation Helpers', () => {
  describe('isValidStixBundle', () => {
    it('should validate correct STIX bundle', () => {
      const bundle = {
        type: 'bundle',
        objects: [{ type: 'indicator', id: 'indicator--123' }]
      };
      expect(isValidStixBundle(bundle)).toBe(true);
    });

    it('should reject bundle with wrong type', () => {
      const bundle = {
        type: 'not-a-bundle',
        objects: [{ type: 'indicator' }]
      };
      expect(isValidStixBundle(bundle)).toBe(false);
    });

    it('should reject bundle without objects', () => {
      const bundle = {
        type: 'bundle'
      };
      expect(isValidStixBundle(bundle)).toBe(false);
    });

    it('should reject bundle with empty objects', () => {
      const bundle = {
        type: 'bundle',
        objects: []
      };
      expect(isValidStixBundle(bundle)).toBe(false);
    });

    it('should reject non-object inputs', () => {
      expect(isValidStixBundle(null)).toBe(false);
      expect(isValidStixBundle(undefined)).toBe(false);
      expect(isValidStixBundle('not-an-object')).toBe(false);
    });
  });

  describe('generateBundleValidationErrorMessage', () => {
    it('should generate error for missing type', () => {
      const bundle = { objects: [] };
      const message = generateBundleValidationErrorMessage(bundle);
      expect(message).toContain('missing "type" property');
    });

    it('should generate error for wrong type', () => {
      const bundle = { type: 'wrong-type', objects: [] };
      const message = generateBundleValidationErrorMessage(bundle);
      expect(message).toContain('type must be "bundle"');
      expect(message).toContain('wrong-type');
    });

    it('should generate error for missing objects', () => {
      const bundle = { type: 'bundle' };
      const message = generateBundleValidationErrorMessage(bundle);
      expect(message).toContain('missing or empty "objects" array');
    });

    it('should generate error for invalid input', () => {
      const message = generateBundleValidationErrorMessage(null);
      expect(message).toContain('does not conform to STIX 2.x format');
    });
  });
});