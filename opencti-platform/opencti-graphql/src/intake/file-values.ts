import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import Upload from 'graphql-upload/Upload.mjs';
import { UploadFile } from './stix-import/types';

// The files of an in-process ingestion write (worker-less intake, POC). Over HTTP a file travels
// as a multipart part and the Upload scalar hands the resolver a promise of a FileUpload. In
// process the transformation keeps it in memory as an UploadFile, the executor turns it into the
// same Upload (withUploads) so that every resolver runs unchanged. The walkers of the variables
// (member marks, echo ids) must step over a file: its Buffer would be walked byte by byte.

// A file, or what stands for one in the variables or in a domain input: never walked
export const isFileValue = (value: unknown): boolean => value instanceof UploadFile
  || value instanceof Upload
  || Buffer.isBuffer(value)
  || ArrayBuffer.isView(value)
  || (value !== null && typeof value === 'object' && typeof (value as { then?: unknown }).then === 'function');

// Only plain objects and arrays are walked: a Date, or any other class instance, is a value
export const isPlainObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object'
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

const containsUploadFile = (value: unknown): boolean => {
  if (value instanceof UploadFile) return true;
  if (isFileValue(value)) return false;
  if (Array.isArray(value)) return value.some(containsUploadFile);
  if (isPlainObject(value)) return Object.values(value).some(containsUploadFile);
  return false;
};

export const uploadFilesOf = (value: unknown, files: UploadFile[] = []): UploadFile[] => {
  if (value instanceof UploadFile) {
    files.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((item) => uploadFilesOf(item, files));
  } else if (isPlainObject(value)) {
    Object.values(value).forEach((item) => uploadFilesOf(item, files));
  }
  return files;
};

// What graphqlUploadExpress gives the Upload scalar for a multipart file
export const toUpload = (file: UploadFile) => {
  const upload = new Upload();
  upload.resolve({ filename: file.name, mimetype: file.mime, encoding: '7bit', createReadStream: () => Readable.from([file.data]) } as any);
  return upload;
};

// The variables with every UploadFile as an Upload (a copy only when there is one)
export const withUploads = (value: unknown): unknown => {
  if (!containsUploadFile(value)) return value;
  if (value instanceof UploadFile) return toUpload(value);
  if (Array.isArray(value)) return value.map(withUploads);
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, withUploads(item)]));
  return value;
};

// The form of a value a key is computed from: a file by its content hash, never its bytes
export const fileKeyForm = (value: unknown): unknown => {
  if (value instanceof UploadFile) {
    return { file: { name: value.name, mime: value.mime, sha256: createHash('sha256').update(value.data).digest('hex') } };
  }
  if (Buffer.isBuffer(value)) return { buffer: createHash('sha256').update(value).digest('hex') };
  if (isFileValue(value)) return { upload: true };
  if (Array.isArray(value)) return value.map(fileKeyForm);
  if (isPlainObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fileKeyForm(item)]));
  return value;
};
