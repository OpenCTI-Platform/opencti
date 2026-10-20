import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { copyFile, readFile, utimes, writeFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { downloadLocalFileRange, streamToString } from '../../../src/database/raw-file-storage';

const TEST_FILE = fileURLToPath(new URL('../../data/test-map-file.pmtiles', import.meta.url));

describe('downloadLocalFileRange', () => {
  it('should return null for non-existent file', async () => {
    const result = await downloadLocalFileRange('/non/existent/file.bin');
    expect(result).toBeNull();
  });

  it('should return full file when no range is provided', async () => {
    const result = await downloadLocalFileRange(TEST_FILE);
    expect(result).not.toBeNull();
    expect(result!.totalSize).toBeGreaterThan(0);
    expect(result!.contentLength).toEqual(result!.totalSize);
    expect(result!.contentRange).toBeUndefined();
    expect(result!.etag).toBeDefined();
    expect(result!.etag).toMatch(/^"bundled-/);
    expect(result!.stream).toBeDefined();
    result!.stream.destroy();
  });

  it('should return partial content for a valid range', async () => {
    const result = await downloadLocalFileRange(TEST_FILE, 'bytes=0-9');
    expect(result).not.toBeNull();
    expect(result!.contentLength).toEqual(10);
    expect(result!.contentRange).toMatch(/^bytes 0-9\//);
    expect(result!.totalSize).toBeGreaterThan(10);
    expect(result!.etag).toBeDefined();
    const content = await streamToString(result!.stream);
    expect(content.length).toEqual(10);
  });

  it('should handle range with no end (open-ended)', async () => {
    const fullResult = await downloadLocalFileRange(TEST_FILE);
    const totalSize = fullResult!.totalSize;
    fullResult!.stream.destroy();

    const start = totalSize - 5;
    const result = await downloadLocalFileRange(TEST_FILE, `bytes=${start}-`);
    expect(result).not.toBeNull();
    expect(result!.contentLength).toEqual(5);
    expect(result!.contentRange).toEqual(`bytes ${start}-${totalSize - 1}/${totalSize}`);
    result!.stream.destroy();
  });

  it('should return full file for invalid range format', async () => {
    const result = await downloadLocalFileRange(TEST_FILE, 'invalid-range');
    expect(result).not.toBeNull();
    expect(result!.contentLength).toEqual(result!.totalSize);
    expect(result!.contentRange).toBeUndefined();
    result!.stream.destroy();
  });

  it('should return consistent etag for same file', async () => {
    const result1 = await downloadLocalFileRange(TEST_FILE);
    const result2 = await downloadLocalFileRange(TEST_FILE, 'bytes=0-5');
    expect(result1!.etag).toEqual(result2!.etag);
    result1!.stream.destroy();
    result2!.stream.destroy();
  });

  it('should keep the etag when only the modification time changes', async () => {
    const copy = join(tmpdir(), `etag-mtime-${Date.now()}.bin`);
    await copyFile(TEST_FILE, copy);
    try {
      const before = await downloadLocalFileRange(copy);
      before!.stream.destroy();
      const later = new Date(Date.now() + 60_000);
      await utimes(copy, later, later);
      const after = await downloadLocalFileRange(copy);
      after!.stream.destroy();
      expect(after!.etag).toEqual(before!.etag);
    } finally {
      await rm(copy, { force: true });
    }
  });

  it('should derive the etag from a digest of the content', async () => {
    const result = await downloadLocalFileRange(TEST_FILE);
    result!.stream.destroy();
    const expected = createHash('sha256')
      .update(await readFile(TEST_FILE))
      .digest('hex')
      .slice(0, 32);
    expect(result!.etag).toEqual(`"bundled-${expected}"`);
  });

  it('should give two files of the same size different etags', async () => {
    const first = join(tmpdir(), `etag-a-${Date.now()}.bin`);
    const second = join(tmpdir(), `etag-b-${Date.now()}.bin`);
    await writeFile(first, 'aaaaaaaaaa');
    await writeFile(second, 'bbbbbbbbbb');
    try {
      const a = await downloadLocalFileRange(first);
      const b = await downloadLocalFileRange(second);
      a!.stream.destroy();
      b!.stream.destroy();
      expect(a!.totalSize).toEqual(b!.totalSize);
      expect(a!.etag).not.toEqual(b!.etag);
    } finally {
      await rm(first, { force: true });
      await rm(second, { force: true });
    }
  });

  it('should clamp an end offset beyond EOF to the actual file size', async () => {
    const fullResult = await downloadLocalFileRange(TEST_FILE);
    const totalSize = fullResult!.totalSize;
    fullResult!.stream.destroy();

    const result = await downloadLocalFileRange(TEST_FILE, `bytes=0-${totalSize + 1000}`);
    expect(result).not.toBeNull();
    expect(result!.rangeNotSatisfiable).toBeFalsy();
    expect(result!.contentLength).toEqual(totalSize);
    expect(result!.contentRange).toEqual(`bytes 0-${totalSize - 1}/${totalSize}`);
    result!.stream.destroy();
  });

  it('should mark the range not satisfiable when start is beyond EOF', async () => {
    const fullResult = await downloadLocalFileRange(TEST_FILE);
    const totalSize = fullResult!.totalSize;
    fullResult!.stream.destroy();

    const result = await downloadLocalFileRange(TEST_FILE, `bytes=${totalSize + 100}-${totalSize + 200}`);
    expect(result).not.toBeNull();
    expect(result!.rangeNotSatisfiable).toBe(true);
    result!.stream.destroy();
  });

  it('should mark the range not satisfiable when start is after end', async () => {
    const result = await downloadLocalFileRange(TEST_FILE, 'bytes=10-5');
    expect(result).not.toBeNull();
    expect(result!.rangeNotSatisfiable).toBe(true);
    result!.stream.destroy();
  });
});
