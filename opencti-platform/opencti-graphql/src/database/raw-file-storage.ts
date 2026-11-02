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
import conf, { booleanConf, confNameToEnvName, isConfKeyDefined, logApp, logS3Debug, resolveRenamedConfKey } from '../config/conf';
import { UnsupportedError } from '../config/errors';
import type { AuthUser } from '../types/user';
import { getRoleAssumerWithWebIdentity, setupAwsClient } from '../utils/awsSdk';

// Object storage configuration, `s3` section. The former `minio` section is still read as an alias.
const STORAGE_CONF_NAMES = ['endpoint', 'port', 'access_key', 'secret_key', 'session_token', 'bucket_name', 'bucket_region',
  'use_ssl', 'use_aws_role', 'use_aws_logs', 'disable_checksum_validation', 'excluded_files', 'credentials_provider'];
export const storageConfKey = (name: string) => resolveRenamedConfKey(`s3:${name}`, `minio:${name}`);

// Former names read (used), former names hidden by a new name (ignored), new names hidden by a former name of higher
// priority (shadowed). Key names only, never values.
export const storageConfDeprecations = () => {
  const userStores = Object.fromEntries(Object.entries(conf.stores).filter(([name]) => name !== 'default'));
  const used: string[] = [];
  const ignored: string[] = [];
  const shadowed: string[] = [];
  STORAGE_CONF_NAMES.forEach((name) => {
    const key = `s3:${name}`;
    const legacyKey = `minio:${name}`;
    if (storageConfKey(name) === legacyKey) {
      used.push(legacyKey);
      if (isConfKeyDefined(key, userStores)) {
        shadowed.push(key);
      }
    } else if (isConfKeyDefined(legacyKey)) {
      ignored.push(legacyKey);
    }
  });
  return { used, ignored, shadowed };
};

export const logStorageConfDeprecations = () => {
  const { used, ignored, shadowed } = storageConfDeprecations();
  const describe = (keys: string[]) => keys.map((key) => `${key} (${confNameToEnvName(key)})`);
  if (used.length > 0) {
    logApp.warn('[FILE STORAGE] The minio configuration section is deprecated, rename it to s3', { keys: describe(used) });
  }
  if (ignored.length > 0) {
    logApp.warn('[FILE STORAGE] Former minio configuration ignored, the s3 name is set', { keys: describe(ignored) });
  }
  if (shadowed.length > 0) {
    logApp.warn('[FILE STORAGE] s3 configuration ignored, a minio name of higher priority is set', { keys: describe(shadowed) });
  }
};
const clientEndpoint = conf.get(storageConfKey('endpoint'));
const clientPort = conf.get(storageConfKey('port')) || 9000;
const clientAccessKey = conf.get(storageConfKey('access_key'));
const clientSecretKey = conf.get(storageConfKey('secret_key'));
const clientSessionToken = conf.get(storageConfKey('session_token'));
const bucketName = conf.get(storageConfKey('bucket_name')) || 'opencti-bucket';
const bucketRegion = conf.get(storageConfKey('bucket_region')) || 'us-east-1';
const useSslConnection = booleanConf(storageConfKey('use_ssl'), false);
const useAwsRole = booleanConf(storageConfKey('use_aws_role'), false);
const useAwsLogs = booleanConf(storageConfKey('use_aws_logs'), false);
const disableChecksumValidation = booleanConf(storageConfKey('disable_checksum_validation'), false);
const credentialsPrefix = storageConfKey('credentials_provider').split(':')[0];
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
  const userPasswordAuth = await enrichWithRemoteCredentials(credentialsPrefix, baseAuth);
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
  logStorageConfDeprecations();
  await initializeFileStorageClient();
  await initializeBucket();
  logApp.info('[CHECK] File Storage is alive');
  return true;
};

export const isStorageAlive = () => initializeBucket();

export const deleteFileFromStorage = async (id: string) => {
  return s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id,
  }));
};

/**
 * Download a file from S3 at given S3 key (id)
 * @param id
 * @returns {Promise<Readable | null>} Readable stream of the file content, or null if file doesn't exist
 * @throws {UnsupportedError} when file body is null or undefined
 */
export const downloadFile = async (id: string): Promise<Readable | null> => {
  try {
    const object = await s3Client.send(new s3.GetObjectCommand({
      Bucket: bucketName,
      Key: id,
    }));
    if (!object || !object.Body) {
      logApp.error('[FILE STORAGE] Cannot retrieve file from S3, null body in response', { fileId: id });
      throw UnsupportedError('File body is null or undefined', { fileId: id });
    }
    return object.Body as Readable;
  } catch (err: any) {
    // If file doesn't exist, return null instead of throwing
    if (err.name === 'NoSuchKey') {
      return null;
    }
    // For other errors, log and throw
    logApp.error('[FILE STORAGE] Cannot retrieve file from S3', { cause: err, fileId: id });
    throw err;
  }
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
      logApp.error('[FILE STORAGE] Cannot retrieve file from S3, null body in response', { fileId: id });
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
    logApp.error('[FILE STORAGE] Cannot retrieve file range from S3', { cause: err, fileId: id });
    throw err;
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
  const object: GetObjectCommandOutput = await s3Client.send(new s3.GetObjectCommand({
    Bucket: bucketName,
    Key: id,
  }));
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
  await s3Client.send(command);
};

/**
 * Get file size from S3 (calling HEAD on S3 file).
 */
export const getFileSize = async (user: AuthUser, fileS3Path: string): Promise<number | undefined> => {
  try {
    const object: HeadObjectCommandOutput = await s3Client.send(new s3.HeadObjectCommand({
      Bucket: bucketName,
      Key: fileS3Path,
    }));
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
  await s3Upload.done();
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
  await s3Upload.done();
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
    throw err;
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
  return s3Client.send(new s3.ListObjectsV2Command(requestParams));
};
