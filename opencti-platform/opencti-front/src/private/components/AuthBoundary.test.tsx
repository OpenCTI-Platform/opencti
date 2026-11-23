import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../utils/tests/test-render';
import { initStaleChunkReload, resetStaleChunkReloadForTests } from '../../utils/staleChunkReload';
import AuthBoundary from './AuthBoundary';

const staleChunkError = new TypeError('Failed to fetch dynamically imported module: https://opencti/assets/PrivateRoot-4RXO6ypR.js');

const Crash = ({ error }: { error: unknown }) => {
  throw error;
};

const renderCrash = (error: unknown) => testRender(
  <AuthBoundary>
    <Crash error={error} />
  </AuthBoundary>,
);

describe('AuthBoundary with a chunk of a previous build', () => {
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
  });

  it('shows nothing while the page reloads to the new build', () => {
    window.dispatchEvent(Object.assign(new Event('vite:preloadError', { cancelable: true }), { payload: staleChunkError }));

    const { container } = renderCrash(staleChunkError);

    expect(container.textContent).toEqual('');
  });

  it('shows the error when no reload is pending', () => {
    const { container } = renderCrash(staleChunkError);

    expect(container.textContent).not.toEqual('');
  });
});
