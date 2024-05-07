import { describe, expect, it } from 'vitest';
import { findAllSupportFiles } from '../../../src/modules/support/support-domain';
import { SUPPORT_LOG_FILE_PREFIX } from '../../../src/config/conf';

describe('Testing support package filesystem tools - findAllSupportFiles', () => {
  it('should find all support files in list', async () => {
    const filesFound = findAllSupportFiles([
      'support.2024-04-23',
      'support.2022-06-29',
      'crapfile.log',
      '.stuff',
      'support.2024-04-28',
      'support.2024-04-27'
    ], SUPPORT_LOG_FILE_PREFIX);

    expect(filesFound.length).toBe(4);
  });

  it('should find all support files even if there is only one', async () => {
    const filesFound = findAllSupportFiles([
      '.caa4b3be024451942bcf5b2b03dc380049c97ba1-audit.json',
      '2b165a0f-6dc9-4c59-9df1-d9c38dd616a6.zip',
      'support.2024-04-08',
    ], SUPPORT_LOG_FILE_PREFIX);

    expect(filesFound.length).toBe(1);
    expect(filesFound[0]).toBe('support.2024-04-08');
  });

  it('should not crash and find nothing on empty list', async () => {
    const fileFound = findAllSupportFiles([], SUPPORT_LOG_FILE_PREFIX);
    expect(fileFound.length).toBe(0);
  });
});
