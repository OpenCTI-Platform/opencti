// What the wizard asks again and again about one uploaded zip (the preview, the dry run of each change of the selection): the zip never
// changes for a file id, and reading it (listing and inflating tens of thousands of files) costs seconds. What is kept of it is the snapshot
// of the bundle (see createConfigPresetBundleSnapshot): one Buffer, a few MB, out of the heap. It is kept in the memory of the node, for a short
// time after its last use. Another node has its own copy: a miss is a read, never an error. A read that failed is not kept.
// The attachments of the items (exclusion lists, fintel designs) are not part of it: they are read from the zip when an importer asks, which
// downloads the zip again. A bundle with attachments is slower than one without, not slower than without this cache.
// The entry also holds the index of the items of the types the preview lists page by page (see getConfigPresetImportIndex). It lives and dies
// with the entry; it is made of live objects (about 250 bytes an item), which is why only the types that are paged are in it, and it is
// not counted in the size limit: a bundle of 50 000 labels holds about 13 MB of it.
import type { ConfigPresetImportIndex } from './configPreset-import-types';

export const CONFIG_PRESET_IMPORT_CACHE_TTL_MS = 15 * 60 * 1000;
// A user works on one zip at a time (a new upload drops the previous one): this is for the few administrators who import at once
export const CONFIG_PRESET_IMPORT_CACHE_MAX_ENTRIES = 2;
// The size of the snapshots kept, whatever their number. A bundle of 50 MB of JSON, the limit of an upload, is not kept: it is read each time
export const CONFIG_PRESET_IMPORT_CACHE_MAX_BYTES = 32 * 1024 * 1024;

interface ConfigPresetImportCacheEntry {
  snapshot: Promise<Buffer>;
  // Known once the snapshot is read
  size: number;
  // What the preview computed of the items of the paged types, shared by the callers that ask while it is computed
  index?: Promise<ConfigPresetImportIndex>;
  timer?: NodeJS.Timeout;
}

const entries = new Map<string, ConfigPresetImportCacheEntry>();

const cacheKey = (userId: string, fileId: string) => `${userId}/${fileId}`;

const forget = (key: string) => {
  const entry = entries.get(key);
  if (entry?.timer) {
    clearTimeout(entry.timer);
  }
  entries.delete(key);
};

// Never keeps the process alive
const armExpiry = (key: string, entry: ConfigPresetImportCacheEntry) => {
  if (entry.timer) {
    clearTimeout(entry.timer);
  }
  entry.timer = setTimeout(() => forget(key), CONFIG_PRESET_IMPORT_CACHE_TTL_MS);
  entry.timer.unref();
};

// The oldest ones go first, until what is kept fits the limits
const enforceLimits = () => {
  let bytes = [...entries.values()].reduce((total, { size }) => total + size, 0);
  const keys = [...entries.keys()];
  for (let i = 0; i < keys.length && (entries.size > CONFIG_PRESET_IMPORT_CACHE_MAX_ENTRIES || bytes > CONFIG_PRESET_IMPORT_CACHE_MAX_BYTES); i += 1) {
    bytes -= entries.get(keys[i])?.size ?? 0;
    forget(keys[i]);
  }
};

// The snapshot of the file of the user, read by load on a miss. The caller checked that the user may read this file: the key holds the user,
// so an entry only exists for a user who was allowed to read it. Concurrent callers share one read.
export const getConfigPresetImportSnapshot = (userId: string, fileId: string, load: () => Promise<Buffer>): Promise<Buffer> => {
  const key = cacheKey(userId, fileId);
  const known = entries.get(key);
  if (known) {
    // Used again: it lives on, and it is the most recent one
    entries.delete(key);
    entries.set(key, known);
    armExpiry(key, known);
    return known.snapshot;
  }
  const entry: ConfigPresetImportCacheEntry = { snapshot: load(), size: 0 };
  entries.set(key, entry);
  armExpiry(key, entry);
  enforceLimits();
  entry.snapshot.then((snapshot) => {
    if (entries.get(key) === entry) {
      entry.size = snapshot.length;
      if (entry.size > CONFIG_PRESET_IMPORT_CACHE_MAX_BYTES) {
        forget(key);
      } else {
        enforceLimits();
      }
    }
  }, () => {
    if (entries.get(key) === entry) {
      forget(key);
    }
  });
  return entry.snapshot;
};

// The index of the paged types of the file, when one is kept. The entry only exists for a user who was allowed to read the file.
export const getConfigPresetImportIndex = (userId: string, fileId: string): Promise<ConfigPresetImportIndex> | undefined => {
  const key = cacheKey(userId, fileId);
  const entry = entries.get(key);
  if (!entry) {
    return undefined;
  }
  // Used again: it lives on
  armExpiry(key, entry);
  return entry.index;
};

// Keeps the index of the file with its entry, replacing the one kept. Nothing is kept when there is no entry (a snapshot too big to be kept),
// and a computation that failed is not kept.
export const setConfigPresetImportIndex = (userId: string, fileId: string, index: Promise<ConfigPresetImportIndex>) => {
  const entry = entries.get(cacheKey(userId, fileId));
  if (entry) {
    entry.index = index;
    index.catch(() => {
      if (entry.index === index) {
        entry.index = undefined;
      }
    });
  }
};

// The file is deleted or replaced (start over, a new upload, the import): what was read of it is of no use any more
export const dropConfigPresetImportCache = (userId: string) => {
  [...entries.keys()].filter((key) => key.startsWith(`${userId}/`)).forEach(forget);
};

export const clearConfigPresetImportCache = () => {
  [...entries.keys()].forEach(forget);
};
