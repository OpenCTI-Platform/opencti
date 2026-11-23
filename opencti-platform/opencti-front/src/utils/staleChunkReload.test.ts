import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { initStaleChunkReload, isReloadingForStaleChunk, isStaleChunkReloadPending, resetStaleChunkReloadForTests } from './staleChunkReload';

// What Vite rejects a lazy import with when a file of a previous build is gone
const chunkError = new TypeError('Failed to fetch dynamically imported module: https://opencti/assets/RootSearch-4RXO6ypR.js');
const cssError = new Error('Unable to preload CSS for /assets/Workflow-4RXO6ypR.css');

const dispatchPreloadError = (payload: unknown) => {
  const event = new Event('vite:preloadError', { cancelable: true }) as Event & { payload?: unknown };
  event.payload = payload;
  window.dispatchEvent(event);
  return event;
};

describe('initStaleChunkReload', () => {
  let reload: Mock<() => void>;
  let dispose: () => void;

  beforeEach(() => {
    sessionStorage.clear();
    resetStaleChunkReloadForTests();
    reload = vi.fn<() => void>();
    dispose = initStaleChunkReload({ reload, now: () => 100_000 });
  });

  afterEach(() => {
    dispose();
    vi.restoreAllMocks();
  });

  it('reloads the page when a chunk of the previous build cannot be loaded', () => {
    dispatchPreloadError(chunkError);

    expect(reload).toHaveBeenCalledTimes(1);
    expect(isStaleChunkReloadPending()).toBe(true);
  });

  it('reloads only once when several chunks fail', () => {
    dispatchPreloadError(chunkError);
    dispatchPreloadError(cssError);

    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('does not reload again when the page was reloaded for the same reason moments ago', () => {
    // The chunk is still missing after a fresh reload: it is a real error, not a stale build
    sessionStorage.setItem('opencti.staleChunkReloadAt', String(100_000 - 30_000));

    dispatchPreloadError(chunkError);

    expect(reload).not.toHaveBeenCalled();
    expect(isStaleChunkReloadPending()).toBe(false);
  });

  it('reloads again once the previous reload is old enough', () => {
    sessionStorage.setItem('opencti.staleChunkReloadAt', String(100_000 - 120_000));

    dispatchPreloadError(chunkError);

    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('does not reload when it cannot remember the reload, which would loop', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('QuotaExceededError');
    });

    dispatchPreloadError(chunkError);

    expect(reload).not.toHaveBeenCalled();
    expect(isStaleChunkReloadPending()).toBe(false);
  });

  it('does not reload when the browser is offline: the chunk is not gone, the network is', () => {
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);

    dispatchPreloadError(chunkError);

    expect(reload).not.toHaveBeenCalled();
    expect(isStaleChunkReloadPending()).toBe(false);
  });

  it('lets the error reach the error boundary, which hides it while the page reloads', () => {
    const event = dispatchPreloadError(chunkError);

    // Vite rethrows the error unless the event is prevented: React.lazy then fails with
    // the original error instead of resolving to undefined
    expect(event.defaultPrevented).toBe(false);
  });
});

describe('isReloadingForStaleChunk', () => {
  let dispose: () => void;

  beforeEach(() => {
    sessionStorage.clear();
    resetStaleChunkReloadForTests();
    dispose = initStaleChunkReload({ reload: () => {} });
  });

  afterEach(() => {
    dispose();
  });

  it.each([
    ['script', chunkError],
    ['stylesheet', cssError],
  ])('is true for the error of a missing %s the page reloads for', (_file, error) => {
    dispatchPreloadError(error);

    expect(isReloadingForStaleChunk(error)).toBe(true);
  });

  it('is true for a file that failed after the reload started', () => {
    dispatchPreloadError(chunkError);
    dispatchPreloadError(cssError);

    expect(isReloadingForStaleChunk(cssError)).toBe(true);
  });

  it('is false for any other error, even while the page reloads', () => {
    dispatchPreloadError(chunkError);

    expect(isReloadingForStaleChunk(new TypeError(chunkError.message))).toBe(false);
    expect(isReloadingForStaleChunk(new TypeError('value.split is not a function'))).toBe(false);
    expect(isReloadingForStaleChunk(undefined)).toBe(false);
  });

  it('is false when no reload is pending', () => {
    sessionStorage.setItem('opencti.staleChunkReloadAt', String(Date.now()));

    dispatchPreloadError(chunkError);

    expect(isReloadingForStaleChunk(chunkError)).toBe(false);
  });
});
