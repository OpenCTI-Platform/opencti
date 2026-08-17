import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import { archiveFolderToZip, findAllSupportFiles } from '../../../src/modules/support/support-domain';
import { SUPPORT_LOG_FILE_PREFIX } from '../../../src/config/conf';

// A valid non-empty ZIP starts with a local file header signature (PK\x03\x04).
const ZIP_LOCAL_FILE_HEADER = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
// An empty ZIP only contains an end-of-central-directory record (PK\x05\x06).
const ZIP_END_OF_CENTRAL_DIR = Buffer.from([0x50, 0x4b, 0x05, 0x06]);

describe('Testing support package filesystem tools - findAllSupportFiles', () => {
  it('should find all support files in list', async () => {
    const filesFound = findAllSupportFiles([
      'support.2024-04-23',
      'support.2022-06-29',
      'crapfile.log',
      '.stuff',
      'support.2024-04-28',
      'support.2024-04-27',
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

describe('Testing support package filesystem tools - archiveFolderToZip', () => {
  let workDir: string;
  let sourceDir: string;
  let zipFullpath: string;

  beforeEach(() => {
    workDir = fs.mkdtempSync(join(os.tmpdir(), 'opencti-support-zip-'));
    sourceDir = join(workDir, 'logs');
    fs.mkdirSync(sourceDir, { recursive: true });
    zipFullpath = join(workDir, 'support.zip');
  });

  afterEach(() => {
    if (fs.existsSync(workDir)) {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it('should create a zip archive containing the folder files', async () => {
    fs.writeFileSync(join(sourceDir, 'support.2024-04-23'), 'first support log content');
    fs.writeFileSync(join(sourceDir, 'support.2024-04-24'), 'second support log content');

    await archiveFolderToZip(sourceDir, zipFullpath);

    expect(fs.existsSync(zipFullpath)).toBe(true);
    expect(fs.statSync(zipFullpath).size).toBeGreaterThan(0);

    // Validate the ZIP structure without a decompression library: entry filenames are
    // stored uncompressed in the local file headers and central directory.
    const zipBuffer = fs.readFileSync(zipFullpath);
    expect(zipBuffer.subarray(0, 4)).toEqual(ZIP_LOCAL_FILE_HEADER);
    expect(zipBuffer.includes('support.2024-04-23')).toBe(true);
    expect(zipBuffer.includes('support.2024-04-24')).toBe(true);
  });

  it('should create an (empty) zip archive when the folder has no files', async () => {
    await archiveFolderToZip(sourceDir, zipFullpath);

    expect(fs.existsSync(zipFullpath)).toBe(true);
    const zipBuffer = fs.readFileSync(zipFullpath);
    // An archive with no entries only holds the end-of-central-directory record.
    expect(zipBuffer.subarray(0, 4)).toEqual(ZIP_END_OF_CENTRAL_DIR);
  });

  it('should throw an error when the zip cannot be written', async () => {
    fs.writeFileSync(join(sourceDir, 'support.2024-04-23'), 'first support log content');
    // Target a path inside a non-existent directory so the output write stream emits an error.
    const invalidZipFullpath = join(workDir, 'non-existent-dir', 'support.zip');

    await expect(archiveFolderToZip(sourceDir, invalidZipFullpath)).rejects.toThrow();
    expect(fs.existsSync(invalidZipFullpath)).toBe(false);
  });
});
