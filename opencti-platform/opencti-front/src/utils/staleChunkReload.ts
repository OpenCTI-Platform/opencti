// After a platform upgrade, a tab still running the previous build asks for chunks
// whose hashed names no longer exist. Reloading once gets the new build.

const RELOAD_AT_KEY = 'opencti.staleChunkReloadAt';
// A file still missing this soon after a reload is not a stale build: do not loop
const MIN_RELOAD_INTERVAL_MS = 60_000;
// A page still there this long after reload() was kept by a beforeunload prompt
const RELOAD_CANCELED_AFTER_MS = 10_000;

// How browsers and Vite word a file that could not be fetched. Vite dispatches the same
// event when a chunk loaded but threw while running: that is a bug, a reload hides it.
const ASSET_LOAD_MESSAGES = [
  'Failed to fetch dynamically imported module', // Chrome, Edge
  'error loading dynamically imported module', // Firefox
  'Importing a module script failed', // Safari
  'Unable to preload CSS for', // Vite, for a stylesheet
];

const isAssetLoadError = (error: unknown): error is Error => {
  return error instanceof Error && ASSET_LOAD_MESSAGES.some((message) => error.message.includes(message));
};

let reloadPending = false;
// What the failed lazy imports rejected with: Vite rethrows these same objects
let preloadErrors = new WeakSet<object>();
let canceledListeners = new Set<() => void>();

export const isStaleChunkReloadPending = (): boolean => reloadPending;

// True when this error is one the page is already reloading for: nothing to show or log
export const isReloadingForStaleChunk = (error: unknown): boolean => {
  return reloadPending && typeof error === 'object' && error !== null && preloadErrors.has(error);
};

// Called when the page is still there after a reload: the hidden errors must show again
export const onStaleChunkReloadCanceled = (listener: () => void): () => void => {
  canceledListeners.add(listener);
  return () => {
    canceledListeners.delete(listener);
  };
};

export const resetStaleChunkReloadForTests = () => {
  reloadPending = false;
  preloadErrors = new WeakSet<object>();
  canceledListeners = new Set<() => void>();
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
  let canceledTimer: ReturnType<typeof setTimeout> | undefined;
  const cancelReload = () => {
    window.removeEventListener('beforeunload', onBeforeUnload);
    reloadPending = false;
    canceledListeners.forEach((listener) => listener());
  };
  const startCanceledTimer = () => {
    clearTimeout(canceledTimer);
    canceledTimer = setTimeout(cancelReload, RELOAD_CANCELED_AFTER_MS);
  };
  // A beforeunload prompt blocks the page until the user answers. A zero timer runs only
  // then: counting from the answer, a user who leaves after a long wait sees no error.
  function onBeforeUnload() {
    clearTimeout(canceledTimer);
    canceledTimer = setTimeout(startCanceledTimer, 0);
  }
  const onPreloadError = (event: Event & { payload?: unknown }) => {
    if (!isAssetLoadError(event.payload)) {
      return;
    }
    preloadErrors.add(event.payload);
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
    window.addEventListener('beforeunload', onBeforeUnload);
    reload();
    startCanceledTimer();
  };
  // Vite dispatches it when a lazy import cannot load a script or stylesheet, then
  // rethrows the error unless the event is prevented: it still reaches the error
  // boundaries, which hide it while the page reloads.
  window.addEventListener('vite:preloadError', onPreloadError);
  return () => {
    window.removeEventListener('vite:preloadError', onPreloadError);
    window.removeEventListener('beforeunload', onBeforeUnload);
    clearTimeout(canceledTimer);
  };
};
