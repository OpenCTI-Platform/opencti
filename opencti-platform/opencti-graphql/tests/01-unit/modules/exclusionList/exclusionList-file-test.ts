import { Readable } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/raw-file-storage', () => ({ downloadFile: vi.fn() }));

import { downloadFile } from '../../../../src/database/raw-file-storage';
import { MAX_FILE_SIZE } from '../../../../src/modules/exclusionList/exclusionList-domain';
import { readExclusionListFile } from '../../../../src/modules/exclusionList/exclusionList-file';

const list = { internal_id: '3f1d0c4e-7a52-4b8e-9f3a-1c2d3e4f5a6b', file_id: 'exclusionLists/3f1d0c4e-7a52-4b8e-9f3a-1c2d3e4f5a6b.txt' };

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Exclusion list file', () => {
  it('reads the file of the list byte for byte, whatever its chunks', async () => {
    const bytes = Buffer.from([0x38, 0x0d, 0x0a, 0xc3, 0xa9, 0xff, 0x00, 0x0a]);
    vi.mocked(downloadFile).mockResolvedValue(Readable.from([bytes.subarray(0, 3), bytes.subarray(3)]));
    expect(await readExclusionListFile(list)).toEqual(bytes);
    expect(downloadFile).toHaveBeenCalledWith(list.file_id);
  });

  it('reads an empty file', async () => {
    vi.mocked(downloadFile).mockResolvedValue(Readable.from([]));
    expect(await readExclusionListFile(list)).toEqual(Buffer.alloc(0));
  });

  it('gives null when the storage has no such file', async () => {
    vi.mocked(downloadFile).mockResolvedValue(null);
    expect(await readExclusionListFile(list)).toBeNull();
  });

  it('throws a storage error, it is not a missing file', async () => {
    vi.mocked(downloadFile).mockRejectedValue(new Error('s3 down'));
    await expect(readExclusionListFile(list)).rejects.toThrow('s3 down');
  });

  // file_id can be patched by whoever edits the lists: the export must not read any other key than the one of the list
  it.each([
    ['the file of another list', 'exclusionLists/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.txt'],
    ['a file of another folder', 'import/global/secret.txt'],
    ['a key that only looks like it', `${list.file_id}/../../import/global/secret.txt`],
    ['an empty key', ''],
  ])('reads nothing when the list points to %s', async (_name, fileId) => {
    expect(await readExclusionListFile({ ...list, file_id: fileId })).toBeNull();
    expect(downloadFile).not.toHaveBeenCalled();
  });

  it('refuses a file bigger than an exclusion list file can be, and stops reading it', async () => {
    const stream = Readable.from([Buffer.alloc(MAX_FILE_SIZE), Buffer.alloc(1), Buffer.alloc(1)]);
    vi.mocked(downloadFile).mockResolvedValue(stream);
    await expect(readExclusionListFile(list)).rejects.toThrow('Exclusion list file too large');
    expect(stream.destroyed).toBe(true);
  });

  it('accepts a file of exactly the maximum size', async () => {
    vi.mocked(downloadFile).mockResolvedValue(Readable.from([Buffer.alloc(MAX_FILE_SIZE)]));
    expect(await readExclusionListFile(list)).toHaveLength(MAX_FILE_SIZE);
  });
});
