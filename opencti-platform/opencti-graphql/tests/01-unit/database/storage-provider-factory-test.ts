import { describe, expect, it } from 'vitest';
import { createStorageProvider, getStorageProvider, STORAGE_PROVIDER_AZURE, STORAGE_PROVIDER_S3 } from '../../../src/database/storage/storage-provider-factory';
import { S3FileStorageProvider } from '../../../src/database/storage/s3-file-storage-provider';
import { AzureFileStorageProvider } from '../../../src/database/storage/azure-file-storage-provider';

describe('storage provider factory', () => {
  it('should default to the S3 provider when no provider is configured (backward compatible)', () => {
    expect(createStorageProvider(undefined)).toBeInstanceOf(S3FileStorageProvider);
    expect(createStorageProvider('')).toBeInstanceOf(S3FileStorageProvider);
    expect(createStorageProvider(STORAGE_PROVIDER_S3)).toBeInstanceOf(S3FileStorageProvider);
  });

  it('should select the Azure provider (case-insensitive)', () => {
    expect(createStorageProvider(STORAGE_PROVIDER_AZURE)).toBeInstanceOf(AzureFileStorageProvider);
    expect(createStorageProvider('AZURE')).toBeInstanceOf(AzureFileStorageProvider);
  });

  it('should throw on an unsupported provider', () => {
    expect(() => createStorageProvider('gcs')).toThrowError(/Unsupported storage provider/);
  });

  it('should memoize the configured provider instance', () => {
    // Default test config has no storage:provider => s3.
    const first = getStorageProvider();
    const second = getStorageProvider();
    expect(first).toBe(second);
    expect(first).toBeInstanceOf(S3FileStorageProvider);
  });
});
