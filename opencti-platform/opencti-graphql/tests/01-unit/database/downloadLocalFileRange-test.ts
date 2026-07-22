import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { downloadLocalFileRange, streamToString } from '../../../src/database/raw-file-storage';

const TEST_FILE = fileURLToPath(new URL('../../data/test-map-tiles.pmtiles', import.meta.url));

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
});
