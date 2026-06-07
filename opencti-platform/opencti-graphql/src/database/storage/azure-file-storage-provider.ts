import { Readable } from 'stream';
import type { BlobItem, BlobServiceClient, ContainerClient } from '@azure/storage-blob';
import conf, { logApp } from '../../config/conf';
import { ConfigurationError, UnsupportedError } from '../../config/errors';
import { type FileStorageProvider, type StorageConnectionConfig, type StorageListResult, type StorageObject, streamToString } from './file-storage-provider';

const azureAccountName = conf.get('storage:azure:account_name');
const azureEndpointSuffix = conf.get('storage:azure:endpoint_suffix') || 'blob.core.windows.net';
const azureContainerName = conf.get('storage:azure:container_name') || 'opencti-bucket';
const azureClientId = conf.get('storage:azure:client_id');
const azureConnectionString = conf.get('storage:azure:connection_string');

const AZURE_UPLOAD_BLOCK_SIZE = 8 * 1024 * 1024;
const AZURE_UPLOAD_CONCURRENCY = 5;
const AZURE_DOWNLOAD_MAX_RETRIES = 5;
const AZURE_LIST_PAGE_SIZE = 1000;

const isBlobNotFound = (err: any): boolean => {
  return err?.statusCode === 404 || err?.code === 'BlobNotFound' || err?.details?.errorCode === 'BlobNotFound';
};

const toStorageObject = (name: string, contentLength?: number, lastModified?: Date): StorageObject => ({
  Key: name,
  Size: contentLength,
  LastModified: lastModified,
});

/**
 * Azure Blob Storage implementation of the storage contract. The Azure container is the analog of
 * the S3 bucket.
 *
 * Authentication uses `DefaultAzureCredential` so a single code path covers Workload Identity (AKS),
 * Managed Identity (VM/VMSS/ACI) and service-principal env vars (CI). A connection string is accepted
 * for local Azurite only. Note: the identity needs the `Storage Blob Data Contributor` role on the
 * account/container, otherwise every call returns `403 AuthorizationPermissionMismatch`.
 */
export class AzureFileStorageProvider implements FileStorageProvider {
  private containerClient!: ContainerClient;

  async initialize(): Promise<void> {
    const { BlobServiceClient } = await import('@azure/storage-blob');
    let serviceClient: BlobServiceClient;
    if (azureConnectionString) {
      // Dev / Azurite path — never use in production (shared-key secret).
      serviceClient = BlobServiceClient.fromConnectionString(azureConnectionString);
    } else {
      if (!azureAccountName) {
        throw ConfigurationError('Azure storage requires storage:azure:account_name (STORAGE__AZURE__ACCOUNT_NAME) when no connection string is provided');
      }
      const { DefaultAzureCredential } = await import('@azure/identity');
      // managedIdentityClientId pins a specific user-assigned identity / workload-identity app.
      const credential = azureClientId
        ? new DefaultAzureCredential({ managedIdentityClientId: azureClientId })
        : new DefaultAzureCredential();
      serviceClient = new BlobServiceClient(`https://${azureAccountName}.${azureEndpointSuffix}`, credential);
    }
    this.containerClient = serviceClient.getContainerClient(azureContainerName);
  }

  async ensureBucket(): Promise<boolean> {
    try {
      await this.containerClient.createIfNotExists();
      return true;
    } catch (err: any) {
      if (err?.statusCode === 403) {
        logApp.error('[FILE STORAGE] Azure authorization failure creating container. '
          + 'Assign the "Storage Blob Data Contributor" role to the identity on the storage account/container.', { cause: err, container: azureContainerName });
      }
      throw err;
    }
  }

  isAlive(): Promise<boolean> {
    // Liveness probe only — does not mutate (unlike the S3 path which head-then-creates).
    return this.containerClient.exists();
  }

  async deleteBucket(): Promise<void> {
    try {
      await this.containerClient.deleteIfExists();
    } catch (err) {
      logApp.info('[FILE STORAGE] Container cannot be deleted.', { err });
    }
  }

  async delete(key: string): Promise<void> {
    const blobClient = this.containerClient.getBlobClient(key);
    await blobClient.deleteIfExists();
  }

  /**
   * @returns Readable stream of the blob content, or null if the blob doesn't exist (parity with S3).
   * @throws {UnsupportedError} when the blob body is null or undefined
   */
  async download(key: string): Promise<Readable | null> {
    try {
      const blockBlobClient = this.containerClient.getBlockBlobClient(key);
      const response = await blockBlobClient.download(0, undefined, { maxRetryRequests: AZURE_DOWNLOAD_MAX_RETRIES });
      const body = response.readableStreamBody;
      if (!body) {
        logApp.error('[FILE STORAGE] Cannot retrieve file from Azure, null body in response', { fileId: key });
        throw UnsupportedError('File body is null or undefined', { fileId: key });
      }
      return body as Readable;
    } catch (err: any) {
      if (isBlobNotFound(err)) {
        return null;
      }
      logApp.error('[FILE STORAGE] Cannot retrieve file from Azure', { cause: err, fileId: key });
      throw err;
    }
  }

  async getContent(key: string, encoding: BufferEncoding = 'utf8'): Promise<string | undefined> {
    // Mirrors S3 getContent: throws (RestError 404, like S3 NoSuchKey) when the blob is missing.
    const blockBlobClient = this.containerClient.getBlockBlobClient(key);
    const response = await blockBlobClient.download(0);
    const body = response.readableStreamBody;
    if (!body) {
      return undefined;
    }
    return streamToString(body, encoding);
  }

  /**
   * Server-side copy. Uses a streamed download→upload (works under Managed Identity without minting a
   * SAS on the source). Copies are infrequent (drafts/exports) so this is acceptable; a future
   * optimization can switch to `syncCopyFromURL` + a short-lived user-delegation SAS.
   */
  async copy(sourceKey: string, targetKey: string): Promise<void> {
    const sourceBlob = this.containerClient.getBlockBlobClient(sourceKey);
    const downloadResponse = await sourceBlob.download(0, undefined, { maxRetryRequests: AZURE_DOWNLOAD_MAX_RETRIES });
    const body = downloadResponse.readableStreamBody;
    if (!body) {
      throw UnsupportedError('Source file body is null or undefined', { sourceKey, targetKey });
    }
    const targetBlob = this.containerClient.getBlockBlobClient(targetKey);
    await targetBlob.uploadStream(body as Readable, AZURE_UPLOAD_BLOCK_SIZE, AZURE_UPLOAD_CONCURRENCY);
  }

  async getSize(key: string): Promise<number | undefined> {
    const blobClient = this.containerClient.getBlobClient(key);
    const properties = await blobClient.getProperties();
    return properties.contentLength;
  }

  async upload(key: string, body: string | Readable | Buffer): Promise<void> {
    const blockBlobClient = this.containerClient.getBlockBlobClient(key);
    if (typeof body === 'string' || Buffer.isBuffer(body)) {
      const buffer = typeof body === 'string' ? Buffer.from(body) : body;
      await blockBlobClient.uploadData(buffer);
    } else {
      // Readable stream — block-staging upload (auto-multipart), bounded memory.
      await blockBlobClient.uploadStream(body, AZURE_UPLOAD_BLOCK_SIZE, AZURE_UPLOAD_CONCURRENCY);
    }
  }

  async list(prefix: string, recursive: boolean, continuationToken?: string): Promise<StorageListResult> {
    const byPageSettings = { continuationToken: continuationToken || undefined, maxPageSize: AZURE_LIST_PAGE_SIZE };
    // Recursive => flat listing of every blob under the prefix.
    // Non-recursive => single virtual folder via delimiter '/'. Only blob items are returned; blob
    // prefixes (sub-folders) are ignored to match the S3 behavior of reading `Contents` only.
    // Branch the byPage().next() per listing kind so each iterator keeps a concrete type.
    const page = recursive
      ? (await this.containerClient.listBlobsFlat({ prefix }).byPage(byPageSettings).next()).value
      : (await this.containerClient.listBlobsByHierarchy('/', { prefix }).byPage(byPageSettings).next()).value;
    if (!page) {
      return { objects: [], isTruncated: false };
    }
    const blobItems: BlobItem[] = page.segment?.blobItems ?? [];
    const objects = blobItems.map((blob) => toStorageObject(blob.name, blob.properties?.contentLength, blob.properties?.lastModified));
    const nextToken = page.continuationToken;
    return {
      objects,
      isTruncated: Boolean(nextToken),
      nextContinuationToken: nextToken || undefined,
    };
  }

  /**
   * Connector connection config (used only by the opt-in connector direct-upload sink). Under Managed
   * Identity there are no static keys, so credentials are returned empty and the sink cannot target
   * the container — a future enhancement can mint a scoped User Delegation SAS here.
   */
  connectionConfig(): StorageConnectionConfig {
    return {
      endpoint: '',
      port: 0,
      use_ssl: true,
      bucket_name: azureContainerName,
      bucket_region: '',
      access_key: '',
      secret_key: '',
    };
  }
}
