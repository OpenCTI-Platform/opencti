// After a platform upgrade, a tab still running the previous build asks for chunks
// whose hashed names no longer exist. Reloading once gets the new build.

const RELOAD_AT_KEY = 'opencti.staleChunkReloadAt';
// A file still missing this soon after a reload is not a stale build: do not loop
const MIN_RELOAD_INTERVAL_MS = 60_000;

let reloadPending = false;
// What the failed lazy imports rejected with: Vite rethrows these same objects
let preloadErrors = new WeakSet<object>();

export const isStaleChunkReloadPending = (): boolean => reloadPending;

// True when this error is one the page is already reloading for: nothing to show or log
export const isReloadingForStaleChunk = (error: unknown): boolean => {
  return reloadPending && typeof error === 'object' && error !== null && preloadErrors.has(error);
};

export const resetStaleChunkReloadForTests = () => {
  reloadPending = false;
  preloadErrors = new WeakSet<object>();
};

const readLastReloadAt = (): number | null => {
  try {
    const value = sessionStorage.getItem(RELOAD_AT_KEY);
    return value === null ? null : Number(value);
  } catch {
    return null;
  }
};

const writeLastReloadAt = (at: number): boolean => {
  try {
    sessionStorage.setItem(RELOAD_AT_KEY, String(at));
    return true;
  } catch {
    return false;
  }
};

interface StaleChunkReloadOptions {
  reload?: () => void;
  now?: () => number;
}

export const initStaleChunkReload = ({
  reload = () => window.location.reload(),
  now = Date.now,
}: StaleChunkReloadOptions = {}): () => void => {
  const onPreloadError = (event: Event & { payload?: unknown }) => {
    if (typeof event.payload === 'object' && event.payload !== null) {
      preloadErrors.add(event.payload);
    }
    if (reloadPending) {
      return;
    }
    // Offline, the file is not gone, the network is: reloading would only lose the page
    if (!navigator.onLine) {
      return;
    }
    const at = now();
    const lastReloadAt = readLastReloadAt();
    if (lastReloadAt !== null && at - lastReloadAt < MIN_RELOAD_INTERVAL_MS) {
      return;
    }
    // Without a way to remember the reload, a missing file would reload forever
    if (!writeLastReloadAt(at)) {
      return;
    }
    reloadPending = true;
    reload();
  };
  // Vite dispatches it when a lazy import cannot load a script or stylesheet, then
  // rethrows the error unless the event is prevented: it still reaches the error
  // boundaries, which hide it while the page reloads.
  window.addEventListener('vite:preloadError', onPreloadError);
  return () => window.removeEventListener('vite:preloadError', onPreloadError);
};
