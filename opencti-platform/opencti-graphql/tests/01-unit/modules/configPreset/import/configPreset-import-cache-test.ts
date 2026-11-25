import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  clearConfigPresetImportCache,
  CONFIG_PRESET_IMPORT_CACHE_MAX_BYTES,
  CONFIG_PRESET_IMPORT_CACHE_MAX_ENTRIES,
  CONFIG_PRESET_IMPORT_CACHE_TTL_MS,
  dropConfigPresetImportCache,
  getConfigPresetImportSnapshot,
} from '../../../../../src/modules/configPreset/import/configPreset-import-cache';

const snapshot = (size = 10) => Buffer.alloc(size);
const loaderOf = (content: Buffer = snapshot()) => vi.fn(async () => content);
// The entry of a read that is over is known to the cache one tick after
const settle = () => vi.advanceTimersByTimeAsync(0);

describe('Config preset import snapshot cache', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    clearConfigPresetImportCache();
    vi.useRealTimers();
  });

  it('reads once for the same user and file, and gives the same snapshot', async () => {
    const load = loaderOf();
    const first = await getConfigPresetImportSnapshot('user', 'file', load);
    const second = await getConfigPresetImportSnapshot('user', 'file', load);
    expect(load).toHaveBeenCalledTimes(1);
    expect(second).toBe(first);
  });

  it('shares one read between callers that ask while it runs', async () => {
    const load = loaderOf();
    await Promise.all([getConfigPresetImportSnapshot('user', 'file', load), getConfigPresetImportSnapshot('user', 'file', load)]);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('keeps one entry per user and per file: another user never gets what was read for this one', async () => {
    const mine = loaderOf(snapshot(1));
    const other = loaderOf(snapshot(2));
    const otherFile = loaderOf(snapshot(3));
    await getConfigPresetImportSnapshot('user', 'file', mine);
    expect((await getConfigPresetImportSnapshot('other-user', 'file', other)).length).toBe(2);
    expect((await getConfigPresetImportSnapshot('user', 'other-file', otherFile)).length).toBe(3);
    expect(mine).toHaveBeenCalledTimes(1);
  });

  it('does not keep a read that failed, and the next call reads again', async () => {
    const load = vi.fn<() => Promise<Buffer>>().mockRejectedValueOnce(new Error('storage down')).mockResolvedValue(snapshot());
    await expect(getConfigPresetImportSnapshot('user', 'file', load)).rejects.toThrow('storage down');
    await settle();
    await getConfigPresetImportSnapshot('user', 'file', load);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('forgets a snapshot a few minutes after its last use, each use postponing it', async () => {
    const load = loaderOf();
    await getConfigPresetImportSnapshot('user', 'file', load);
    await vi.advanceTimersByTimeAsync(CONFIG_PRESET_IMPORT_CACHE_TTL_MS - 1000);
    await getConfigPresetImportSnapshot('user', 'file', load);
    await vi.advanceTimersByTimeAsync(CONFIG_PRESET_IMPORT_CACHE_TTL_MS - 1000);
    await getConfigPresetImportSnapshot('user', 'file', load);
    expect(load).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(CONFIG_PRESET_IMPORT_CACHE_TTL_MS + 1000);
    await getConfigPresetImportSnapshot('user', 'file', load);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('forgets everything of a user, and only of this user', async () => {
    const mine = loaderOf();
    const other = loaderOf();
    await getConfigPresetImportSnapshot('user', 'file', mine);
    await getConfigPresetImportSnapshot('user', 'second-file', mine);
    await getConfigPresetImportSnapshot('other-user', 'file', other);
    dropConfigPresetImportCache('user');
    await getConfigPresetImportSnapshot('user', 'file', mine);
    await getConfigPresetImportSnapshot('other-user', 'file', other);
    expect(mine).toHaveBeenCalledTimes(3);
    expect(other).toHaveBeenCalledTimes(1);
  });

  it('keeps a few entries only: the oldest one goes first, the one used again stays', async () => {
    const loads = Array.from({ length: CONFIG_PRESET_IMPORT_CACHE_MAX_ENTRIES + 1 }, () => loaderOf());
    await getConfigPresetImportSnapshot('user', 'file-0', loads[0]);
    await getConfigPresetImportSnapshot('user', 'file-1', loads[1]);
    // file-0 is used again, so file-1 is the oldest
    await getConfigPresetImportSnapshot('user', 'file-0', loads[0]);
    await getConfigPresetImportSnapshot('user', 'file-2', loads[2]);
    await settle();
    await getConfigPresetImportSnapshot('user', 'file-0', loads[0]);
    expect(loads[0]).toHaveBeenCalledTimes(1);
    await getConfigPresetImportSnapshot('user', 'file-1', loads[1]);
    expect(loads[1]).toHaveBeenCalledTimes(2);
  });

  it('keeps the snapshots within a size, the oldest ones going first', async () => {
    const big = snapshot(Math.floor(CONFIG_PRESET_IMPORT_CACHE_MAX_BYTES * 0.6));
    const first = loaderOf(big);
    const second = loaderOf(big);
    await getConfigPresetImportSnapshot('user', 'file-0', first);
    await settle();
    await getConfigPresetImportSnapshot('user', 'file-1', second);
    await settle();
    // Both do not fit: the first one is gone, the second one is kept
    await getConfigPresetImportSnapshot('user', 'file-1', second);
    expect(second).toHaveBeenCalledTimes(1);
    await getConfigPresetImportSnapshot('user', 'file-0', first);
    expect(first).toHaveBeenCalledTimes(2);
  });

  it('gives a snapshot above the size to the caller that asked, and does not keep it nor push the others out', async () => {
    const small = loaderOf(snapshot(10));
    const huge = loaderOf(snapshot(CONFIG_PRESET_IMPORT_CACHE_MAX_BYTES + 1));
    await getConfigPresetImportSnapshot('user', 'small', small);
    await settle();
    expect((await getConfigPresetImportSnapshot('user', 'huge', huge)).length).toBe(CONFIG_PRESET_IMPORT_CACHE_MAX_BYTES + 1);
    await settle();
    await getConfigPresetImportSnapshot('user', 'huge', huge);
    expect(huge).toHaveBeenCalledTimes(2);
    await getConfigPresetImportSnapshot('user', 'small', small);
    expect(small).toHaveBeenCalledTimes(1);
  });
});
