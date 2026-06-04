import type { Readable } from 'stream';

export interface StorageObject {
  Key: string;
  Size?: number;
  LastModified?: Date;
}

/** Backend-agnostic listing result, replacing the S3-specific `ListObjectsV2CommandOutput`. */
export interface StorageListResult {
  objects: StorageObject[];
  isTruncated: boolean;
  nextContinuationToken?: string;
}

export interface StorageConnectionConfig {
  endpoint: string;
  port: number;
  use_ssl: boolean;
  bucket_name: string;
  bucket_region: string;
  access_key: string;
  secret_key: string;
}

export interface FileStorageProvider {
  initialize: () => Promise<void>;
  ensureBucket: () => Promise<boolean>;
  isAlive: () => Promise<boolean>;
  deleteBucket: () => Promise<void>;
  upload: (key: string, body: string | Readable | Buffer) => Promise<void>;
  download: (key: string) => Promise<Readable | null>;
  getContent: (key: string, encoding?: BufferEncoding) => Promise<string | undefined>;
  getSize: (key: string) => Promise<number | undefined>;
  copy: (sourceKey: string, targetKey: string) => Promise<void>;
  delete: (key: string) => Promise<void>;
  list: (prefix: string, recursive: boolean, continuationToken?: string) => Promise<StorageListResult>;
  connectionConfig: () => StorageConnectionConfig;
}

export const streamToString = (stream: any, encoding: BufferEncoding = 'utf8'): Promise<string> => {
  return new Promise((resolve, reject) => {
    if (!stream) {
      reject(new Error('Stream is null or undefined'));
      return;
    }
    const chunks: Uint8Array[] = [];
    stream?.on('data', (chunk: Uint8Array) => chunks.push(chunk));
    stream?.on('error', reject);
    stream?.on('end', () => resolve(Buffer.concat(chunks).toString(encoding)));
  });
};
