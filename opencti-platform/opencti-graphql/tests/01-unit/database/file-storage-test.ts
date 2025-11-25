import { describe, expect, it } from 'vitest';
import { getFileName, guessMimeType, isFileObjectExcluded, storeFileConverter, specialTypesExtensions } from '../../../src/database/file-storage';
import type { LoadedFile } from '../../../src/database/file-storage';
import type { AuthUser } from '../../../src/types/user';

describe('file-storage utility functions', () => {
  describe('getFileName', () => {
    it('should extract filename with extension from full path', () => {
      const result = getFileName('import/global/test-file.json');
      expect(result).toBe('test-file.json');
    });

    it('should handle paths with multiple directories', () => {
      const result = getFileName('import/entities/reports/document.pdf');
      expect(result).toBe('document.pdf');
    });

    it('should handle filename without directory', () => {
      const result = getFileName('simple.txt');
      expect(result).toBe('simple.txt');
    });

    it('should handle files with multiple dots in name', () => {
      const result = getFileName('path/to/my.test.file.json');
      expect(result).toBe('my.test.file.json');
    });

    it('should handle files without extension', () => {
      const result = getFileName('path/to/README');
      expect(result).toBe('README');
    });
  });

  describe('guessMimeType', () => {
    it('should detect JSON mime type', () => {
      const result = guessMimeType('path/file.json');
      expect(result).toBe('application/json');
    });

    it('should detect PDF mime type', () => {
      const result = guessMimeType('document.pdf');
      expect(result).toBe('application/pdf');
    });

    it('should detect text mime type', () => {
      const result = guessMimeType('file.txt');
      expect(result).toBe('text/plain');
    });

    it('should detect image mime types', () => {
      expect(guessMimeType('image.png')).toBe('image/png');
      expect(guessMimeType('image.jpg')).toBe('image/jpeg');
      expect(guessMimeType('image.gif')).toBe('image/gif');
    });

    it('should return octet-stream for unknown extensions', () => {
      const result = guessMimeType('file.unknownext');
      expect(result).toBe('application/octet-stream');
    });

    it('should handle files without extension', () => {
      const result = guessMimeType('path/to/README');
      expect(result).toBe('application/octet-stream');
    });

    it('should handle STIX bundle files', () => {
      const result = guessMimeType('bundle.json');
      expect(result).toBe('application/json');
    });

    it('should be case-insensitive for common types', () => {
      expect(guessMimeType('FILE.PDF')).toBe('application/pdf');
      expect(guessMimeType('FILE.JSON')).toBe('application/json');
    });
  });

  describe('isFileObjectExcluded', () => {
    it('should exclude .DS_Store files', () => {
      const result = isFileObjectExcluded('path/to/.DS_Store');
      expect(result).toBe(true);
    });

    it('should exclude .DS_Store regardless of path', () => {
      const result = isFileObjectExcluded('import/global/.DS_Store');
      expect(result).toBe(true);
    });

    it('should be case-insensitive for exclusion', () => {
      const result = isFileObjectExcluded('path/.ds_store');
      expect(result).toBe(true);
    });

    it('should not exclude normal files', () => {
      expect(isFileObjectExcluded('path/document.pdf')).toBe(false);
      expect(isFileObjectExcluded('import/file.json')).toBe(false);
      expect(isFileObjectExcluded('data.csv')).toBe(false);
    });

    it('should not exclude files with DS_Store in name but not exact match', () => {
      const result = isFileObjectExcluded('path/my_DS_Store_backup.txt');
      expect(result).toBe(false);
    });
  });

  describe('storeFileConverter', () => {
    const mockUser: AuthUser = {
      id: 'user-123',
      user_email: 'test@example.com',
    } as AuthUser;

    it('should convert LoadedFile to x_opencti_file format', () => {
      const file: LoadedFile = {
        id: 'file-id-123',
        name: 'test.pdf',
        size: 1024,
        information: '',
        lastModified: new Date(),
        lastModifiedSinceMin: 0,
        metaData: {
          version: '1.0',
          mimetype: 'application/pdf',
          file_markings: ['marking-1', 'marking-2']
        },
        uploadStatus: 'complete'
      };

      const result = storeFileConverter(mockUser, file);

      expect(result).toEqual({
        id: 'file-id-123',
        name: 'test.pdf',
        version: '1.0',
        mime_type: 'application/pdf',
        file_markings: ['marking-1', 'marking-2']
      });
    });

    it('should handle file without markings', () => {
      const file: LoadedFile = {
        id: 'file-id-456',
        name: 'document.json',
        size: 2048,
        information: '',
        lastModified: new Date(),
        lastModifiedSinceMin: 0,
        metaData: {
          version: '2.0',
          mimetype: 'application/json'
        },
        uploadStatus: 'complete'
      };

      const result = storeFileConverter(mockUser, file);

      expect(result).toEqual({
        id: 'file-id-456',
        name: 'document.json',
        version: '2.0',
        mime_type: 'application/json',
        file_markings: []
      });
    });

    it('should handle file without version', () => {
      const file: LoadedFile = {
        id: 'file-id-789',
        name: 'report.txt',
        size: 512,
        information: '',
        lastModified: new Date(),
        lastModifiedSinceMin: 0,
        metaData: {
          mimetype: 'text/plain',
          file_markings: []
        },
        uploadStatus: 'complete'
      };

      const result = storeFileConverter(mockUser, file);

      expect(result).toEqual({
        id: 'file-id-789',
        name: 'report.txt',
        version: undefined,
        mime_type: 'text/plain',
        file_markings: []
      });
    });

    it('should handle empty metadata', () => {
      const file: LoadedFile = {
        id: 'file-id-empty',
        name: 'empty.dat',
        size: 0,
        information: '',
        lastModified: new Date(),
        lastModifiedSinceMin: 0,
        metaData: {},
        uploadStatus: 'complete'
      };

      const result = storeFileConverter(mockUser, file);

      expect(result).toEqual({
        id: 'file-id-empty',
        name: 'empty.dat',
        version: undefined,
        mime_type: undefined,
        file_markings: []
      });
    });
  });

  describe('specialTypesExtensions', () => {
    it('should have correct STIX extension mapping', () => {
      expect(specialTypesExtensions['application/vnd.oasis.stix+json']).toBe('json');
    });

    it('should have correct MITRE Navigator extension mapping', () => {
      expect(specialTypesExtensions['application/vnd.mitre.navigator+json']).toBe('json');
    });
  });
});
