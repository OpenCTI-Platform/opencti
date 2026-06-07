import type { Readable } from 'stream';
import conf, { logApp } from '../config/conf';
import { UnsupportedError } from '../config/errors';
import type { AuthUser } from '../types/user';
import { type StorageListResult, streamToString } from './storage/file-storage-provider';
import { getStorageProvider } from './storage/storage-provider-factory';

/**
 * Public storage facade. This module used to wrap the AWS S3 SDK directly; it is now a thin,
 * provider-agnostic facade over {@link FileStorageProvider} (S3/MinIO or Azure Blob). The exported
 * function names and signatures are unchanged so every consumer stays untouched.
 */

export { streamToString };
export type { StorageObject, StorageListResult, StorageConnectionConfig } from './storage/file-storage-provider';

export const defaultValidationMode = conf.get('app:validation_mode');

const provider = getStorageProvider();

/** @deprecated Use {@link storageInit} instead. */
export const initializeFileStorageClient = async () => {
  await provider.initialize();
};

/** @deprecated Use {@link storageInit} instead. */
export const initializeBucket = async () => provider.ensureBucket();

export const deleteBucket = async () => provider.deleteBucket();

export const isStorageAlive = () => provider.isAlive();

export const storageInit = async () => {
  logApp.info('[CHECK] Checking if File Storage is available');
  await provider.initialize();
  await provider.ensureBucket();
  logApp.info('[CHECK] File Storage is alive');
  return true;
};

export const deleteFileFromStorage = async (id: string) => provider.delete(id);

/**
 * Download a file from storage at the given key (id).
 * @returns {Promise<Readable | null>} Readable stream of the file content, or null if file doesn't exist
 */
export const downloadFile = (id: string): Promise<Readable | null> => provider.download(id);

export const getFileContent = (id: string, encoding: BufferEncoding = 'utf8'): Promise<string | undefined> => provider.getContent(id, encoding);

export const rawCopyFile = async (sourceId: string, targetId: string) => provider.copy(sourceId, targetId);

export const getFileSize = async (user: AuthUser, fileS3Path: string): Promise<number | undefined> => {
  try {
    return await provider.getSize(fileS3Path);
  } catch (err) {
    throw UnsupportedError('Load file from storage fail', { cause: err, user_id: user.id, filename: fileS3Path });
  }
};

export const rawUpload = async (key: string, body: string | Readable | Buffer) => provider.upload(key, body);

export const rawListObjects = (directory: string, recursive: boolean, continuationToken?: string): Promise<StorageListResult> => {
  return provider.list(directory, recursive, continuationToken);
};

/**
 * Export the active provider's connection configuration for connectors (direct-upload).
 * Kept named `s3ConnectionConfig` for backward compatibility with consumers and the GraphQL schema.
 */
export const s3ConnectionConfig = () => provider.connectionConfig();
