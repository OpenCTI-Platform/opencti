import conf, { logApp } from '../../config/conf';
import { ConfigurationError } from '../../config/errors';
import type { FileStorageProvider } from './file-storage-provider';
import { S3FileStorageProvider } from './s3-file-storage-provider';
import { AzureFileStorageProvider } from './azure-file-storage-provider';

export const STORAGE_PROVIDER_S3 = 's3';
export const STORAGE_PROVIDER_AZURE = 'azure';

export const createStorageProvider = (providerName?: string): FileStorageProvider => {
  const selected = String(providerName || STORAGE_PROVIDER_S3).toLowerCase();
  if (selected === STORAGE_PROVIDER_AZURE) {
    logApp.info('[FILE STORAGE] Using Azure Blob Storage provider');
    return new AzureFileStorageProvider();
  }
  if (selected === STORAGE_PROVIDER_S3) {
    return new S3FileStorageProvider();
  }
  throw ConfigurationError(`Unsupported storage provider '${selected}', expected '${STORAGE_PROVIDER_S3}' or '${STORAGE_PROVIDER_AZURE}'`);
};

let providerInstance: FileStorageProvider | undefined;

/**
 * Resolve the configured storage provider. Defaults to `s3` (which reads the historical `minio:`
 * config) so existing deployments are unaffected. One provider per deployment, memoized for the
 * process lifetime.
 */
export const getStorageProvider = (): FileStorageProvider => {
  if (!providerInstance) {
    providerInstance = createStorageProvider(conf.get('storage:provider'));
  }
  return providerInstance;
};
