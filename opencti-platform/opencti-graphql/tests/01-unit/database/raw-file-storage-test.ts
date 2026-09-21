import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockSend = vi.fn();

vi.mock('@aws-sdk/client-s3', () => {
  class S3Client {
    send = mockSend;
  }
  class ListObjectsV2Command {
    input: unknown;

    constructor(input: unknown) {
      this.input = input;
    }
  }
  return {
    S3Client,
    ListObjectsV2Command,
    CopyObjectCommand: class {},
    HeadBucketCommand: class {},
    CreateBucketCommand: class {},
    DeleteBucketCommand: class {},
    GetObjectCommand: class {},
    HeadObjectCommand: class {},
    DeleteObjectCommand: class {},
    DeleteObjectsCommand: class {},
    PutObjectCommand: class {},
  };
});

vi.mock('@aws-sdk/credential-provider-node', () => ({
  defaultProvider: vi.fn(() => vi.fn()),
}));

vi.mock('@aws-sdk/lib-storage', () => ({
  Upload: class {},
}));

vi.mock('../../../src/config/credentials', () => ({
  enrichWithRemoteCredentials: vi.fn(async (_key: string, auth: unknown) => auth),
}));

vi.mock('../../../src/config/conf', () => ({
  default: { get: vi.fn(() => undefined) },
  booleanConf: vi.fn(() => false),
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
  logS3Debug: { info: vi.fn() },
}));

vi.mock('../../../src/utils/awsSdk', () => ({
  setupAwsClient: vi.fn((client: unknown) => client),
  getRoleAssumerWithWebIdentity: vi.fn(() => vi.fn()),
}));

import { getStorageUsedSize, initializeFileStorageClient } from '../../../src/database/raw-file-storage';

describe('raw-file-storage: getStorageUsedSize', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    await initializeFileStorageClient();
  });

  it('should sum the size of every object of a single page', async () => {
    mockSend.mockResolvedValueOnce({ Contents: [{ Size: 100 }, { Size: 250 }], IsTruncated: false });

    const result = await getStorageUsedSize();

    expect(result).toBe(350);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should follow the continuation token until the listing is complete', async () => {
    mockSend
      .mockResolvedValueOnce({ Contents: [{ Size: 10 }], IsTruncated: true, NextContinuationToken: 'page-2' })
      .mockResolvedValueOnce({ Contents: [{ Size: 20 }], IsTruncated: true, NextContinuationToken: 'page-3' })
      .mockResolvedValueOnce({ Contents: [{ Size: 30 }], IsTruncated: false });

    const result = await getStorageUsedSize();

    expect(result).toBe(60);
    expect(mockSend).toHaveBeenCalledTimes(3);
    const sentTokens = mockSend.mock.calls.map(([command]) => command.input.ContinuationToken);
    expect(sentTokens).toEqual([undefined, 'page-2', 'page-3']);
  });

  it('should return 0 when the bucket is empty', async () => {
    mockSend.mockResolvedValueOnce({ IsTruncated: false });

    const result = await getStorageUsedSize();

    expect(result).toBe(0);
  });

  it('should count objects without a declared size as 0', async () => {
    mockSend.mockResolvedValueOnce({ Contents: [{ Size: 100 }, {}], IsTruncated: false });

    const result = await getStorageUsedSize();

    expect(result).toBe(100);
  });

  it('should scan the whole bucket recursively', async () => {
    mockSend.mockResolvedValueOnce({ Contents: [], IsTruncated: false });

    await getStorageUsedSize();

    const [command] = mockSend.mock.calls[0];
    expect(command.input.Prefix).toBe('');
    expect(command.input.Delimiter).toBeUndefined();
  });

  it('should propagate storage errors instead of reporting a size', async () => {
    mockSend.mockRejectedValueOnce(new Error('S3 unreachable'));

    await expect(getStorageUsedSize()).rejects.toThrow('S3 unreachable');
  });
});
