import { Readable } from 'stream';
import { join } from 'node:path';
import fs from 'node:fs';
import { upload } from './file-storage';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase } from '../types/store';

interface FileUploadOpts {
  entity?:BasicStoreBase | unknown,
  meta? : any,
  noTriggerImport?: boolean,
  errorOnExisting?: boolean,
}

interface FileUploadData {
  createReadStream: () => Readable,
  filename: string,
  mimeType?: string,
}

/**
 * Upload a file (as ReadStream) to S3 or equivalent storage.
 * @param context
 * @param user
 * @param filePath path in S3 storage, should contain only '/', do not use fs.join() to create path (no '\').
 * @param fileUpload
 * @param opts
 */
export const uploadToStorage = (context: AuthContext, user: AuthUser, filePath: string, fileUpload: FileUploadData, opts: FileUploadOpts) => {
  return upload(context, user, filePath, fileUpload, opts);
};

/**
 * Creates a stream to read a file on filesystem.
 * @param localFilePath full path to file, do not append filename
 * @param localFileName
 * @param mimeType
 */
export const fileToReadStream = (localFilePath: string, localFileName: string, s3FileName: string, mimeType: string) => {
  const fullPathFile = join(localFilePath, localFileName);
  const buffer = fs.readFileSync(fullPathFile);
  return { createReadStream: () => Readable.from(buffer), filename: s3FileName, mimetype: mimeType };
};
