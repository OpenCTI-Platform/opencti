import * as s3 from '@aws-sdk/client-s3';
import {
  CopyObjectCommand,
  type GetObjectCommandOutput,
  type HeadObjectCommandOutput,
  type ListObjectsV2CommandInput,
  type ListObjectsV2CommandOutput,
  S3Client,
  type S3ClientConfig
} from '@aws-sdk/client-s3';
import { getDefaultRoleAssumerWithWebIdentity } from '@aws-sdk/client-sts';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { Upload } from '@aws-sdk/lib-storage';
import type { Readable } from 'stream';
import { enrichWithRemoteCredentials } from '../config/credentials';
import conf, { booleanConf, logApp, logS3Debug } from '../config/conf';
import { UnsupportedError } from '../config/errors';
import type { AuthUser } from '../types/user';

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

let s3Client: S3Client; // Client reference

const buildCredentialProvider = async () => {
  // If aws role must be used
  if (useAwsRole) {
    return () => {
      return defaultProvider({
        roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity({
          // You must explicitly pass a region if you are not using us-east-1
          region: bucketRegion
        })
      });
    };
  }
  // If direct configuration
  const baseAuth = { accessKeyId: clientAccessKey, secretAccessKey: clientSecretKey };
  const userPasswordAuth = await enrichWithRemoteCredentials('minio', baseAuth);
  return () => {
    return {
      ...userPasswordAuth,
      ...(clientSessionToken && { sessionToken: clientSessionToken })
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
  s3Client = new s3.S3Client(s3Config);
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
  await initializeFileStorageClient();
  await initializeBucket();
};

export const isStorageAlive = () => initializeBucket();

export const deleteFileFromStorage = async (id: string) => {
  return s3Client.send(new s3.DeleteObjectCommand({
    Bucket: bucketName,
    Key: id
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
      Key: id
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
    Key: id
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
    Key: targetId
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
      Key: fileS3Path
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
      Body: body
    }
  });
  await s3Upload.done();
};

export const rawListObjects = async (directory: string, recursive: boolean, continuationToken?: string): Promise<ListObjectsV2CommandOutput> => {
  const requestParams: ListObjectsV2CommandInput = {
    Bucket: bucketName,
    Prefix: directory,
    Delimiter: recursive ? undefined : '/'
  };
  if (continuationToken) {
    requestParams.ContinuationToken = continuationToken;
  }
  return s3Client.send(new s3.ListObjectsV2Command(requestParams));
};
