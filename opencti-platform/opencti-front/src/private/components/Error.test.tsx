import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../utils/tests/test-render';
import { logger } from '../../utils/logging/logger';
import { initStaleChunkReload, resetStaleChunkReloadForTests } from '../../utils/staleChunkReload';
import { ErrorBoundary } from './Error';

vi.mock('../../utils/logging/logger', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../utils/logging/logger')>();
  return { ...original, logger: { ...original.logger, error: vi.fn() } };
});

const staleChunkError = new TypeError('Failed to fetch dynamically imported module: https://opencti/assets/RootSearch-4RXO6ypR.js');

const Crash = ({ error }: { error: unknown }) => {
  throw error;
};

const renderCrash = (error: unknown) => testRender(
  <ErrorBoundary>
    <Crash error={error} />
  </ErrorBoundary>,
);

describe('ErrorBoundary with a chunk of a previous build', () => {
  let dispose: () => void;

  beforeEach(() => {
    // React logs the errors its boundaries catch
    vi.spyOn(console, 'error').mockImplementation(() => {});
    sessionStorage.clear();
    resetStaleChunkReloadForTests();
    dispose = initStaleChunkReload({ reload: () => {} });
  });

  afterEach(() => {
    dispose();
    vi.mocked(console.error).mockRestore();
    vi.mocked(logger.error).mockClear();
  });

  it('neither logs nor shows the error while the page reloads to the new build', () => {
    const event = Object.assign(new Event('vite:preloadError', { cancelable: true }), { payload: staleChunkError });
    window.dispatchEvent(event);

    const { container } = renderCrash(staleChunkError);

    expect(logger.error).not.toHaveBeenCalled();
    expect(container.textContent).toEqual('');
  });

  it('logs and shows the error when no reload is pending', () => {
    // The chunk is still missing right after a reload: a real error
    const { container } = renderCrash(staleChunkError);

    expect(logger.error).toHaveBeenCalledWith('React component tree crashed', expect.objectContaining({ error: staleChunkError }));
    expect(container.textContent).not.toEqual('');
  });
});
