import { Readable } from 'node:stream';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { type GetObjectCommandOutput, S3Client, S3ServiceException } from '@aws-sdk/client-s3';
import { logApp } from '../../../src/config/conf';
import { downloadFileWithoutLogging, initializeFileStorageClient } from '../../../src/database/raw-file-storage';

const KEY = 'sync/inflight/sync-id-1/remote-file-1/content';

const buildS3Error = (name: string): S3ServiceException => {
  return new S3ServiceException({ name, $fault: 'client', $metadata: { httpStatusCode: 403 }, message: 'Access Denied.' });
};

describe('downloadFileWithoutLogging', () => {
  beforeAll(async () => {
    await initializeFileStorageClient();
  });

  beforeEach(() => {
    vi.spyOn(logApp, 'error');
    vi.spyOn(logApp, 'warn');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return the object body', async () => {
    const body = Readable.from(['content']);
    vi.spyOn(S3Client.prototype, 'send').mockImplementation(async () => ({ Body: body, $metadata: {} }) as GetObjectCommandOutput);
    const stream = await downloadFileWithoutLogging(KEY);
    expect(stream).toBe(body);
  });

  it('should return null when the key does not exist', async () => {
    vi.spyOn(S3Client.prototype, 'send').mockImplementation(async () => {
      throw buildS3Error('NoSuchKey');
    });
    const stream = await downloadFileWithoutLogging(KEY);
    expect(stream).toBeNull();
  });

  it('should rethrow other S3 errors without logging the key', async () => {
    const s3Error = buildS3Error('AccessDenied');
    vi.spyOn(S3Client.prototype, 'send').mockImplementation(async () => {
      throw s3Error;
    });
    await expect(downloadFileWithoutLogging(KEY)).rejects.toBe(s3Error);
    expect(logApp.error).not.toHaveBeenCalled();
    expect(logApp.warn).not.toHaveBeenCalled();
  });

  it('should throw without the key in the error when the body is missing', async () => {
    vi.spyOn(S3Client.prototype, 'send').mockImplementation(async () => ({ $metadata: {} }) as GetObjectCommandOutput);
    const error = await downloadFileWithoutLogging(KEY).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(Error);
    expect(JSON.stringify(error)).not.toContain('remote-file-1');
    expect((error as Error).message).not.toContain('remote-file-1');
    expect(logApp.error).not.toHaveBeenCalled();
  });
});
