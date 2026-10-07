import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { memoizeAsync } from '../utils/memoize';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import * as s3 from '@aws-sdk/client-s3';
import {
  CopyObjectCommand,
  type GetObjectCommandOutput,
  type HeadObjectCommandOutput,
  type ListObjectsV2CommandInput,
  type ListObjectsV2CommandOutput,
  S3Client,
  type S3ClientConfig,
} from '@aws-sdk/client-s3';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { Upload } from '@aws-sdk/lib-storage';
import { enrichWithRemoteCredentials } from '../config/credentials';
import conf, { booleanConf, logApp, logS3Debug } from '../config/conf';
import { InfraError, UnsupportedError } from '../config/errors';
import { APP_MODULE, isNetworkFailure, tagErrorModule } from '../config/error-origin';
import type { AuthUser } from '../types/user';
import { getRoleAssumerWithWebIdentity, setupAwsClient } from '../utils/awsSdk';

// Minio configuration
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
export const defaultValidationMode = conf.get('app:validation_mode');

/**
 * Export S3 connection configuration for connectors.
 * This allows connectors to upload bundles directly to S3 storage.
 */
export const s3ConnectionConfig = () => ({
  endpoint: clientEndpoint,
  port: clientPort,
  use_ssl: useSslConnection,
  bucket_name: bucketName,
  bucket_region: bucketRegion,
  access_key: clientAccessKey,
  secret_key: clientSecretKey,
});

let s3Client: S3Client; // Client reference

// region error classification (RFC 0006)
// The SDK already retried, so a failure left here is final for the caller.
const isS3Unavailable = (err: any) => {
  if (isNetworkFailure(err) || err?.name === 'TimeoutError') {
    return true;
  }
  const status = err?.$metadata?.httpStatusCode;
  return err?.$fault === 'server' || (typeof status === 'number' && (status >= 500 || status === 429));
};

// - The service is unavailable or failing: a typed infra error, `origin: infra`.
// - A bug in this client or in the SDK: tagged `core`, `origin: code`.
// - The service rejected our request (4xx): untouched, the calling module owns it.
export const classifyS3Error = (err: unknown, operation: string) => {
  if (isS3Unavailable(err)) {
    return InfraError('s3', 'File storage is unavailable', { operation, cause: err });
  }
  if (err instanceof TypeError) {
    return tagErrorModule(err, APP_MODULE.CORE);
  }
  return err;
};

const s3Call = async <T>(operation: string, call: () => Promise<T>): Promise<T> => {
  try {
    return await call();
  } catch (err) {
    throw classifyS3Error(err, operation);
  }
};
// endregion

const buildCredentialProvider = async () => {
  // If aws role must be used
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
  // If direct configuration
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

export const initializeFileStorageClient = async () => {
  const s3Config: S3ClientConfig = {
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
  s3Client = setupAwsClient(new s3.S3Client(s3Config));
};

export const initializeBucket = async () => {
  try {
    // Try to access to the bucket
    await s3Client.send(new s3.HeadBucketCommand({ Bucket: bucketName }));
    return true;
  } catch (_err) {
    // If bucket not exist, try to create it.
    // If creation fail, propagate the exception
    await s3Client.send(new s3.CreateBucketCommand({ Bucket: bucketName }));
    return true;
  }
};

export const deleteBucket = async () => {
  try {
    // Try to access to the bucket
    await s3Client.send(new s3.DeleteBucketCommand({ Bucket: bucketName }));
  } catch (err) {
    // Dont care
    logApp.info('[FILE STORAGE] Bucket cannot be deleted.', { err });
  }
};

export const storageInit = async () => {
  logApp.info('[CHECK] Checking if File Storage is available');
  await initializeFileStorageClient();
  await initializeBucket();
  logApp.info('[CHECK] File Storage is alive');
  return true;
};

export const isStorageAlive = () => initializeBucket();

export const deleteFileFromStorage = async (id: string) => {
  return s3Call('delete', () => s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id,
  })));
};

/**
 * Download a file from S3 at given S3 key (id)
 * @param id
 * @returns {Promise<Readable | null>} Readable stream of the file content, or null if file doesn't exist
 * @throws {UnsupportedError} when file body is null or undefined
 * @throws {InfraError} when the file storage is unavailable
 */
export const downloadFile = async (id: string): Promise<Readable | null> => {
  let object: GetObjectCommandOutput;
  try {
    object = await s3Client.send(new s3.GetObjectCommand({
      Bucket: bucketName,
      Key: id,
    }));
  } catch (err: any) {
    // If file doesn't exist, return null instead of throwing
    if (err.name === 'NoSuchKey') {
      return null;
    }
    // Logged by the error boundary that catches it.
    throw classifyS3Error(err, 'download');
  }
  if (!object || !object.Body) {
    throw UnsupportedError('File body is null or undefined', { fileId: id });
  }
  return object.Body as Readable;
};

export interface RangeDownloadResult {
  stream: Readable;
  contentLength: number;
  contentRange?: string;
  totalSize: number;
  etag?: string;
  rangeNotSatisfiable?: boolean;
}

export const downloadFileRange = async (id: string, range?: string): Promise<RangeDownloadResult | null> => {
  let totalSize = 0;
  try {
    // First get file size via HEAD
    const head = await s3Client.send(new s3.HeadObjectCommand({
      Bucket: bucketName,
      Key: id,
    }));
    totalSize = head.ContentLength ?? 0;

    const getParams: s3.GetObjectCommandInput = {
      Bucket: bucketName,
      Key: id,
    };
    if (range) {
      getParams.Range = range;
    }

    const object = await s3Client.send(new s3.GetObjectCommand(getParams));
    if (!object || !object.Body) {
      throw UnsupportedError('File body is null or undefined', { fileId: id });
    }
    return {
      stream: object.Body as Readable,
      contentLength: object.ContentLength ?? totalSize,
      contentRange: object.ContentRange,
      totalSize,
      etag: head.ETag,
    };
  } catch (err: any) {
    if (err.name === 'NoSuchKey' || err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404) {
      return null;
    }
    if (err.name === 'InvalidRange' || err.$metadata?.httpStatusCode === 416) {
      return { stream: Readable.from([]), contentLength: 0, totalSize, rangeNotSatisfiable: true };
    }
    // Logged by the error boundary that catches it.
    throw classifyS3Error(err, 'download_range');
  }
};

const localFileEtag = memoizeAsync(async (filePath: string): Promise<string> => {
  const hash = createHash('sha256');
  await pipeline(createReadStream(filePath), hash);
  return `"bundled-${hash.digest('hex').slice(0, 32)}"`;
}, (filePath) => filePath);

export const downloadLocalFileRange = async (filePath: string, range?: string): Promise<RangeDownloadResult | null> => {
  let fileStat;
  try {
    fileStat = await stat(filePath);
  } catch {
    return null;
  }
  const totalSize = fileStat.size;
  const etag = await localFileEtag(filePath);
  if (range) {
    const match = range.match(/bytes=(\d+)-(\d*)/);
    if (match) {
      const start = parseInt(match[1], 10);
      const end = match[2] ? Math.min(parseInt(match[2], 10), totalSize - 1) : totalSize - 1;
      if (start > end || start >= totalSize) {
        return { stream: Readable.from([]), contentLength: 0, totalSize, etag, rangeNotSatisfiable: true };
      }
      const contentLength = end - start + 1;
      return {
        stream: createReadStream(filePath, { start, end }),
        contentLength,
        contentRange: `bytes ${start}-${end}/${totalSize}`,
        totalSize,
        etag,
      };
    }
  }
  return { stream: createReadStream(filePath), contentLength: totalSize, totalSize, etag };
};

export const streamToString = (stream: any, encoding: BufferEncoding = 'utf8'): Promise<string> => {
  return new Promise((resolve, reject) => {
    if (!stream) {
      reject();
    }
    const chunks: Uint8Array[] = [];
    stream?.on('data', (chunk: Uint8Array) => chunks.push(chunk));
    stream?.on('error', reject);
    stream?.on('end', () => resolve(Buffer.concat(chunks).toString(encoding)));
  });
};

export const getFileContent = async (id: string, encoding: BufferEncoding = 'utf8'): Promise<string | undefined> => {
  const object: GetObjectCommandOutput = await s3Call('get_content', () => s3Client.send(new s3.GetObjectCommand({
    Bucket: bucketName,
    Key: id,
  })));
  if (!object.Body) {
    return undefined;
  }
  return streamToString(object.Body, encoding);
};

export const rawCopyFile = async (sourceId: string, targetId: string) => {
  const input = {
    Bucket: bucketName,
    CopySource: `${bucketName}/${sourceId}`, // CopySource must start with bucket name, but not Key
    Key: targetId,
  };
  const command = new CopyObjectCommand(input);
  await s3Call('copy', () => s3Client.send(command));
};

/**
 * Get file size from S3 (calling HEAD on S3 file).
 */
export const getFileSize = async (user: AuthUser, fileS3Path: string): Promise<number | undefined> => {
  try {
    const object: HeadObjectCommandOutput = await s3Call('head', () => s3Client.send(new s3.HeadObjectCommand({
      Bucket: bucketName,
      Key: fileS3Path,
    })));
    return object.ContentLength;
  } catch (err) {
    throw UnsupportedError('Load file from storage fail', { cause: err, user_id: user.id, filename: fileS3Path });
  }
};

export const rawUpload = async (key: string, body: string | Readable | Buffer) => {
  const s3Upload = new Upload({
    client: s3Client,
    params: {
      Bucket: bucketName,
      Key: key,
      Body: body,
    },
  });
  await s3Call('upload', () => s3Upload.done());
};

export interface FileMetadata {
  contentDisposition?: string;
  contentLength?: number;
  etag?: string;
}

export const rawUploadWithMetadata = async (key: string, body: Readable | Buffer, contentDisposition?: string, contentEncoding?: string) => {
  const s3Upload = new Upload({
    client: s3Client,
    params: {
      Bucket: bucketName,
      Key: key,
      Body: body,
      ContentDisposition: contentDisposition,
      ContentEncoding: contentEncoding,
    },
  });
  await s3Call('upload', () => s3Upload.done());
};

export const getFileMetadata = async (key: string): Promise<FileMetadata | null> => {
  try {
    const head = await s3Client.send(new s3.HeadObjectCommand({ Bucket: bucketName, Key: key }));
    return {
      contentDisposition: head.ContentDisposition,
      contentLength: head.ContentLength,
      etag: head.ETag,
    };
  } catch (err: any) {
    if (err.name === 'NoSuchKey' || err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404) {
      return null;
    }
    throw classifyS3Error(err, 'head');
  }
};

export const rawListObjects = async (directory: string, recursive: boolean, continuationToken?: string): Promise<ListObjectsV2CommandOutput> => {
  const requestParams: ListObjectsV2CommandInput = {
    Bucket: bucketName,
    Prefix: directory,
    Delimiter: recursive ? undefined : '/',
  };
  if (continuationToken) {
    requestParams.ContinuationToken = continuationToken;
  }
  return s3Call('list', () => s3Client.send(new s3.ListObjectsV2Command(requestParams)));
};
