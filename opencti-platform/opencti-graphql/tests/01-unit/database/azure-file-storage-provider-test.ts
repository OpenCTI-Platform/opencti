import { describe, expect, it, vi } from 'vitest';
import { Readable } from 'stream';
import { RestError } from '@azure/storage-blob';
import { AzureFileStorageProvider } from '../../../src/database/storage/azure-file-storage-provider';

const makePage = (names: string[], continuationToken: string) => ({
  segment: {
    blobItems: names.map((name) => ({ name, properties: { contentLength: name.length, lastModified: new Date('2026-01-01') } })),
  },
  continuationToken,
});

const injectContainer = (provider: AzureFileStorageProvider, container: unknown) => {
  (provider as unknown as { containerClient: unknown }).containerClient = container;
};

describe('AzureFileStorageProvider', () => {
  describe('list pagination mapping', () => {
    it('should map a recursive (flat) page to StorageListResult and carry the continuation token', async () => {
      const provider = new AzureFileStorageProvider();
      injectContainer(provider, {
        listBlobsFlat: () => ({ byPage: () => ({ next: async () => ({ value: makePage(['import/a.json', 'import/b.json'], 'TOKEN-2') }) }) }),
      });
      const result = await provider.list('import/', true);
      expect(result.objects.map((o) => o.Key)).toEqual(['import/a.json', 'import/b.json']);
      expect(result.objects[0].Size).toBe('import/a.json'.length);
      expect(result.isTruncated).toBe(true);
      expect(result.nextContinuationToken).toBe('TOKEN-2');
    });

    it('should map a non-recursive (hierarchy) page using delimiter "/" and report not-truncated on empty token', async () => {
      const provider = new AzureFileStorageProvider();
      let usedDelimiter: string | undefined;
      injectContainer(provider, {
        listBlobsByHierarchy: (delimiter: string) => {
          usedDelimiter = delimiter;
          return { byPage: () => ({ next: async () => ({ value: makePage(['export/file.json'], '') }) }) };
        },
      });
      const result = await provider.list('export/', false);
      expect(usedDelimiter).toBe('/');
      expect(result.objects.map((o) => o.Key)).toEqual(['export/file.json']);
      expect(result.isTruncated).toBe(false);
      expect(result.nextContinuationToken).toBeUndefined();
    });

    it('should return an empty result when the page is undefined (iterator done)', async () => {
      const provider = new AzureFileStorageProvider();
      injectContainer(provider, {
        listBlobsFlat: () => ({ byPage: () => ({ next: async () => ({ value: undefined, done: true }) }) }),
      });
      const result = await provider.list('import/', true);
      expect(result.objects).toEqual([]);
      expect(result.isTruncated).toBe(false);
    });
  });

  describe('download not-found mapping', () => {
    it('should return null when the blob does not exist (RestError 404, parity with S3 NoSuchKey)', async () => {
      const provider = new AzureFileStorageProvider();
      injectContainer(provider, {
        getBlockBlobClient: () => ({
          download: async () => {
            throw new RestError('not found', { statusCode: 404 });
          },
        }),
      });
      const result = await provider.download('missing');
      expect(result).toBeNull();
    });

    it('should return the readable stream body when the blob exists', async () => {
      const provider = new AzureFileStorageProvider();
      const body = Readable.from(['hello']);
      injectContainer(provider, {
        getBlockBlobClient: () => ({ download: async () => ({ readableStreamBody: body }) }),
      });
      const result = await provider.download('exists');
      expect(result).toBe(body);
    });

    it('should rethrow non-404 errors', async () => {
      const provider = new AzureFileStorageProvider();
      injectContainer(provider, {
        getBlockBlobClient: () => ({
          download: async () => {
            throw new RestError('server error', { statusCode: 500 });
          },
        }),
      });
      await expect(provider.download('boom')).rejects.toThrow();
    });
  });

  describe('upload routing', () => {
    it('should use uploadData for string/Buffer bodies and uploadStream for readable streams', async () => {
      const provider = new AzureFileStorageProvider();
      const uploadData = vi.fn(async () => {});
      const uploadStream = vi.fn(async () => {});
      injectContainer(provider, { getBlockBlobClient: () => ({ uploadData, uploadStream }) });
      await provider.upload('k1', 'a string');
      await provider.upload('k2', Buffer.from('buf'));
      await provider.upload('k3', Readable.from(['stream']));
      expect(uploadData).toHaveBeenCalledTimes(2);
      expect(uploadStream).toHaveBeenCalledTimes(1);
    });
  });
});
