import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from './logger';
import { initLogger } from './loggerProvider';
import { initStaleChunkReload, resetStaleChunkReloadForTests } from '../staleChunkReload';

vi.mock('./logger', async (importOriginal) => {
  const original = await importOriginal<typeof import('./logger')>();
  return { ...original, logger: { ...original.logger, error: vi.fn() } };
});

const staleChunkError = new TypeError('Failed to fetch dynamically imported module: https://opencti/assets/Graph-4RXO6ypR.js');

const dispatchUnhandledRejection = (reason: unknown) => {
  window.dispatchEvent(Object.assign(new Event('unhandledrejection'), { reason }));
};

describe('unhandled promise rejections', () => {
  let dispose: () => void;

  beforeEach(() => {
    initLogger(true);
    sessionStorage.clear();
    resetStaleChunkReloadForTests();
    dispose = initStaleChunkReload({ reload: () => {} });
  });

  afterEach(() => {
    dispose();
    vi.mocked(logger.error).mockClear();
  });

  it('are not logged when a chunk of the previous build is missing and the page reloads', () => {
    window.dispatchEvent(Object.assign(new Event('vite:preloadError', { cancelable: true }), { payload: staleChunkError }));

    dispatchUnhandledRejection(staleChunkError);

    expect(logger.error).not.toHaveBeenCalled();
  });

  it('are logged otherwise', () => {
    dispatchUnhandledRejection(staleChunkError);

    expect(logger.error).toHaveBeenCalledWith('Unhandled promise rejection', expect.objectContaining({ error: staleChunkError }));
  });
});
