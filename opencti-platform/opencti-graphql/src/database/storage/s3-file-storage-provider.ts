import * as s3 from '@aws-sdk/client-s3';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { Upload } from '@aws-sdk/lib-storage';
import type { Readable } from 'stream';
import { enrichWithRemoteCredentials } from '../../config/credentials';
import conf, { booleanConf, logApp, logS3Debug } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { getRoleAssumerWithWebIdentity, setupAwsClient } from '../../utils/awsSdk';
import { type FileStorageProvider, type StorageConnectionConfig, type StorageListResult, streamToString } from './file-storage-provider';

// S3 / MinIO configuration. Read from the historical `minio:` block for backward compatibility.
const clientEndpoint = conf.get('minio:endpoint');
const clientPort = conf.get('minio:port') || 9000;
const clientAccessKey = conf.get('minio:access_key');
const clientSecretKey = conf.get('minio:secret_key');
const clientSessionToken = conf.get('minio:session_token');
const bucketName = conf.get('minio:bucket_name') || 'opencti-bucket';
const bucketRegion = conf.get('minio:bucket_region') || 'us-east-1';
const useSslConnection = booleanConf('minio:use_ssl', false);
const useAwsRole = booleanConf('minio:use_aws_role', false);
const useAwsLogs = booleanConf('minio:use_aws_logs', false);
const disableChecksumValidation = booleanConf('minio:disable_checksum_validation', false);

const buildCredentialProvider = async () => {
  if (useAwsRole) {
    return () => {
      return defaultProvider({
        roleAssumerWithWebIdentity: getRoleAssumerWithWebIdentity({
          // You must explicitly pass a region if you are not using us-east-1
          region: bucketRegion,
        }),
      });
    };
  }
  const baseAuth = { accessKeyId: clientAccessKey, secretAccessKey: clientSecretKey };
  const userPasswordAuth = await enrichWithRemoteCredentials('minio', baseAuth);
  return () => {
    return {
      ...userPasswordAuth,
      ...(clientSessionToken && { sessionToken: clientSessionToken }),
    };
  };
};

const getEndpoint = () => {
  // If using AWS S3, unset the endpoint to let the library choose the best endpoint
  if (clientEndpoint === 's3.amazonaws.com') {
    return undefined;
  }
  return `${(useSslConnection ? 'https' : 'http')}://${clientEndpoint}:${clientPort}`;
};

/**
 * S3 / MinIO implementation of the storage contract. Holds every S3-ism (endpoint special-case,
 * forcePathStyle, bucket_region, checksum flags) so it never leaks past this module.
 */
export class S3FileStorageProvider implements FileStorageProvider {
  private client!: s3.S3Client;

  async initialize(): Promise<void> {
    const s3Config: s3.S3ClientConfig = {
      region: bucketRegion,
      endpoint: getEndpoint(),
      forcePathStyle: true,
      credentialDefaultProvider: await buildCredentialProvider(),
      tls: useSslConnection,
      requestChecksumCalculation: disableChecksumValidation ? 'WHEN_REQUIRED' : 'WHEN_SUPPORTED',
      responseChecksumValidation: disableChecksumValidation ? 'WHEN_REQUIRED' : 'WHEN_SUPPORTED',
    };
    if (useAwsLogs) {
      s3Config.logger = logS3Debug;
    }
    this.client = setupAwsClient(new s3.S3Client(s3Config));
  }

  async ensureBucket(): Promise<boolean> {
    try {
      await this.client.send(new s3.HeadBucketCommand({ Bucket: bucketName }));
      return true;
    } catch (_err) {
      // Bucket missing — create it; propagate if creation fails.
      await this.client.send(new s3.CreateBucketCommand({ Bucket: bucketName }));
      return true;
    }
  }

  isAlive(): Promise<boolean> {
    return this.ensureBucket();
  }

  async deleteBucket(): Promise<void> {
    try {
      await this.client.send(new s3.DeleteBucketCommand({ Bucket: bucketName }));
    } catch (err) {
      logApp.info('[FILE STORAGE] Bucket cannot be deleted.', { err });
    }
  }

  async delete(key: string): Promise<void> {
    await this.client.send(new s3.DeleteObjectCommand({
      Bucket: bucketName,
      Key: key,
    }));
  }

  /**
   * Download a file from S3 at given S3 key (id).
   * @returns Readable stream of the file content, or null if file doesn't exist
   * @throws {UnsupportedError} when file body is null or undefined
   */
  async download(key: string): Promise<Readable | null> {
    try {
      const object = await this.client.send(new s3.GetObjectCommand({
        Bucket: bucketName,
        Key: key,
      }));
      if (!object || !object.Body) {
        logApp.error('[FILE STORAGE] Cannot retrieve file from S3, null body in response', { fileId: key });
        throw UnsupportedError('File body is null or undefined', { fileId: key });
      }
      return object.Body as Readable;
    } catch (err: any) {
      if (err.name === 'NoSuchKey') {
        return null;
      }
      logApp.error('[FILE STORAGE] Cannot retrieve file from S3', { cause: err, fileId: key });
      throw err;
    }
  }

  async getContent(key: string, encoding: BufferEncoding = 'utf8'): Promise<string | undefined> {
    const object: s3.GetObjectCommandOutput = await this.client.send(new s3.GetObjectCommand({
      Bucket: bucketName,
      Key: key,
    }));
    if (!object.Body) {
      return undefined;
    }
    return streamToString(object.Body, encoding);
  }

  async copy(sourceKey: string, targetKey: string): Promise<void> {
    const input = {
      Bucket: bucketName,
      CopySource: `${bucketName}/${sourceKey}`, // CopySource must start with bucket name, but not Key
      Key: targetKey,
    };
    const command = new s3.CopyObjectCommand(input);
    await this.client.send(command);
  }

  async getSize(key: string): Promise<number | undefined> {
    const object: s3.HeadObjectCommandOutput = await this.client.send(new s3.HeadObjectCommand({
      Bucket: bucketName,
      Key: key,
    }));
    return object.ContentLength;
  }

  async upload(key: string, body: string | Readable | Buffer): Promise<void> {
    const s3Upload = new Upload({
      client: this.client,
      params: {
        Bucket: bucketName,
        Key: key,
        Body: body,
      },
    });
    await s3Upload.done();
  }

  async list(prefix: string, recursive: boolean, continuationToken?: string): Promise<StorageListResult> {
    const requestParams: s3.ListObjectsV2CommandInput = {
      Bucket: bucketName,
      Prefix: prefix,
      Delimiter: recursive ? undefined : '/',
    };
    if (continuationToken) {
      requestParams.ContinuationToken = continuationToken;
    }
    const response = await this.client.send(new s3.ListObjectsV2Command(requestParams));
    const objects = (response.Contents ?? [])
      .filter((obj): obj is s3._Object & { Key: string } => obj.Key !== undefined)
      .map((obj) => ({ Key: obj.Key, Size: obj.Size, LastModified: obj.LastModified }));
    return {
      objects,
      isTruncated: response.IsTruncated ?? false,
      nextContinuationToken: response.NextContinuationToken,
    };
  }

  /**
   * Export S3 connection configuration for connectors.
   * This allows connectors to upload bundles directly to S3 storage.
   */
  connectionConfig(): StorageConnectionConfig {
    return {
      endpoint: clientEndpoint,
      port: clientPort,
      use_ssl: useSslConnection,
      bucket_name: bucketName,
      bucket_region: bucketRegion,
      access_key: clientAccessKey,
      secret_key: clientSecretKey,
    };
  }
}
