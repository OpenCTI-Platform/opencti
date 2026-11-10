import { logger } from './logger';

// Failures caused by the browser environment rather than by a bug: a tab still running a build
// that an upgrade replaced, or a request that never got a response. No code change can fix them,
// so they are logged at warn instead of error.

export const CHUNK_LOAD_FAILED_EVENT_NAME = 'opencti.frontend.chunk_load_failed';
export const NETWORK_FAILED_EVENT_NAME = 'opencti.frontend.network_failed';
export const CHUNK_RELOAD_EVENT_NAME = 'opencti.frontend.chunk_reload';

export const CHUNK_RELOAD_STORAGE_KEY = 'opencti.chunk_reload_at';
export const CHUNK_RELOAD_COOLDOWN_MS = 60_000;

const CHUNK_LOAD_MESSAGES = [
  'Failed to fetch dynamically imported module', // Chrome
  'error loading dynamically imported module', // Firefox
  'Importing a module script failed', // Safari
  'Unable to preload CSS', // Vite preload helper
];

// Exact messages of a fetch() rejected without any response
const NETWORK_FAILURE_MESSAGES = [
  'Failed to fetch', // Chrome
  'NetworkError when attempting to fetch resource.', // Firefox
  'Load failed', // Safari
];

export const isChunkLoadError = (error: unknown): boolean => {
  const message = error instanceof Error ? error.message : error;
  return typeof message === 'string' && CHUNK_LOAD_MESSAGES.some((chunkMessage) => message.includes(chunkMessage));
};

export const isNetworkFailure = (error: unknown): boolean => {
  return error instanceof Error && error.name === 'TypeError' && NETWORK_FAILURE_MESSAGES.includes(error.message);
};

// Records the reload in sessionStorage, which survives it, so that a chunk still missing after the
// reload shows the error fallback instead of reloading in a loop. Without usable storage the loop
// cannot be prevented, so no reload is attempted.
export const claimChunkReload = (now: number = Date.now()): boolean => {
  try {
    const lastReloadAt = Number(window.sessionStorage.getItem(CHUNK_RELOAD_STORAGE_KEY));
    if (lastReloadAt > 0 && Math.abs(now - lastReloadAt) < CHUNK_RELOAD_COOLDOWN_MS) {
      return false;
    }
    window.sessionStorage.setItem(CHUNK_RELOAD_STORAGE_KEY, String(now));
    return true;
  } catch {
    return false;
  }
};

// index.html is never cached, so a reload loads the current build and its chunk names.
export const reloadOnceForChunkError = (error: unknown, reload: () => void = () => window.location.reload()): boolean => {
  if (!claimChunkReload()) {
    return false;
  }
  logger.info('Reloading the page to load the current build', { eventName: CHUNK_RELOAD_EVENT_NAME, error });
  reload();
  return true;
};

// Returns false, without logging, for any other error, so that the caller logs it as before.
export const warnIfEnvironmentFailure = (error: unknown, data?: Record<string, unknown>): boolean => {
  if (isChunkLoadError(error)) {
    logger.warn('Code chunk failed to load', { eventName: CHUNK_LOAD_FAILED_EVENT_NAME, error, data });
    return true;
  }
  if (isNetworkFailure(error)) {
    logger.warn('Network request failed without a response', { eventName: NETWORK_FAILED_EVENT_NAME, error, data });
    return true;
  }
  return false;
};
