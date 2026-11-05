import type { Readable } from 'node:stream';
import Upload from 'graphql-upload/Upload.mjs';
import { deleteFileFromStorage, downloadFile, rawUpload } from '../database/raw-file-storage';
import { isFileValue, isPlainObject, toUpload } from './file-values';
import { UploadFile } from './stix-import/types';

// The files of a retained write (worker-less intake, POC). A retained operation or intent is
// persisted as JSON and re-executed later, possibly after a restart: its files cannot ride the
// JSON. They are staged in the object storage under STAGING_PATH, the JSON keeps a reference,
// the re-execution reads them back, and they are deleted once the record is settled (applied,
// handed, expired or failed).

export const STAGING_PATH = 'intake-staging';

interface StagedFile {
  staged_file: { key: string; name: string; mime: string };
}
interface StagedUpload {
  staged_upload: { key: string; filename: string; mimetype: string; encoding?: string };
}

const isStagedFile = (value: any): value is StagedFile => value !== null && typeof value === 'object' && typeof value.staged_file?.key === 'string';
const isStagedUpload = (value: any): value is StagedUpload => value !== null && typeof value === 'object' && typeof value.staged_upload?.key === 'string';

const streamToBuffer = async (stream: Readable): Promise<Buffer> => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
};

export interface FileStorage {
  upload: (key: string, data: Buffer) => Promise<unknown>;
  download: (key: string) => Promise<Buffer>;
  remove: (key: string) => Promise<unknown>;
}

export const objectFileStorage: FileStorage = {
  upload: (key, data) => rawUpload(key, data),
  download: async (key) => {
    const stream = await downloadFile(key);
    if (!stream) throw new Error(`Staged file ${key} is missing`);
    return streamToBuffer(stream);
  },
  remove: (key) => deleteFileFromStorage(key),
};

// Stage the files of `value` (an operation's variables, an intent's domain input): an UploadFile,
// an Upload, or the promise of a FileUpload the Upload scalar gives a resolver
export const stageFiles = async (value: unknown, prefix: string, storage: FileStorage = objectFileStorage) => {
  const keys: string[] = [];
  const nextKey = () => {
    const key = `${STAGING_PATH}/${prefix}/${keys.length}`;
    keys.push(key);
    return key;
  };
  const stage = async (item: unknown): Promise<unknown> => {
    if (item instanceof UploadFile) {
      const key = nextKey();
      await storage.upload(key, item.data);
      return { staged_file: { key, name: item.name, mime: item.mime } } satisfies StagedFile;
    }
    if (isFileValue(item) && !Buffer.isBuffer(item) && !ArrayBuffer.isView(item)) {
      const upload: any = await (item instanceof Upload ? (item as any).promise : item);
      const key = nextKey();
      await storage.upload(key, await streamToBuffer(upload.createReadStream()));
      return { staged_upload: { key, filename: upload.filename, mimetype: upload.mimetype, encoding: upload.encoding } } satisfies StagedUpload;
    }
    if (Array.isArray(item)) {
      const staged = [];
      for (const element of item) staged.push(await stage(element));
      return staged;
    }
    if (isPlainObject(item)) {
      const staged: Record<string, unknown> = {};
      for (const [key, element] of Object.entries(item)) staged[key] = await stage(element);
      return staged;
    }
    return item;
  };
  const staged = await stage(value);
  return { value: staged, keys };
};

// The value of a staged one: an UploadFile for an operation, the promise of a FileUpload (what the
// Upload scalar gives the resolver, then the domain) for an intent
export const rehydrateFiles = async (value: unknown, storage: FileStorage = objectFileStorage): Promise<unknown> => {
  if (isStagedFile(value)) {
    return new UploadFile(value.staged_file.name, await storage.download(value.staged_file.key), value.staged_file.mime);
  }
  if (isStagedUpload(value)) {
    const { key, filename, mimetype } = value.staged_upload;
    return (toUpload(new UploadFile(filename, await storage.download(key), mimetype)) as any).promise;
  }
  if (Array.isArray(value)) {
    const rehydrated = [];
    for (const element of value) rehydrated.push(await rehydrateFiles(element, storage));
    return rehydrated;
  }
  if (isPlainObject(value)) {
    const rehydrated: Record<string, unknown> = {};
    for (const [key, element] of Object.entries(value)) rehydrated[key] = await rehydrateFiles(element, storage);
    return rehydrated;
  }
  return value;
};

export const removeStagedFiles = async (keys: string[], storage: FileStorage = objectFileStorage) => {
  for (const key of keys) {
    await storage.remove(key);
  }
};
