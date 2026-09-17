import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CATALOG_POLLING_INTERVAL_MS } from '../catalog-constants';
import useCatalogPolling from './useCatalogPolling';

const mocks = vi.hoisted(() => ({
  fetchQuery: vi.fn(),
}));

vi.mock('../../../../../relay/environment', () => ({
  fetchQuery: mocks.fetchQuery,
}));

type RevisionsPayload = {
  catalogsRevisions: Array<{ catalog_id: string; revision: string | null }>;
};

const setDocumentHidden = (hidden: boolean) => {
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => hidden,
  });
};

const mockFetchSequence = (steps: Array<RevisionsPayload | Error>) => {
  let index = 0;
  mocks.fetchQuery.mockImplementation(() => ({
    toPromise: () => {
      const current = steps[Math.min(index, steps.length - 1)];
      index += 1;
      if (current instanceof Error) {
        return Promise.reject(current);
      }
      return Promise.resolve(current);
    },
  }));
};

const flushPromises = async () => {
  await Promise.resolve();
  await Promise.resolve();
};

describe('useCatalogPolling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    setDocumentHidden(false);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('seeds baseline without triggering a full catalogs refresh', async () => {
    mockFetchSequence([
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
    ]);
    const onChanged = vi.fn();

    renderHook(() => useCatalogPolling({ enabled: true, onCatalogRevisionsChanged: onChanged }));
    await act(async () => {
      await flushPromises();
    });

    expect(mocks.fetchQuery).toHaveBeenCalledWith(
      expect.anything(),
      {},
      { fetchPolicy: 'network-only' },
    );

    expect(onChanged).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS);
      await flushPromises();
    });

    expect(onChanged).not.toHaveBeenCalled();
  });

  it('refreshes catalogs when a revision changes and updates baseline', async () => {
    mockFetchSequence([
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-2' }] },
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-2' }] },
    ]);
    const onChanged = vi.fn();

    renderHook(() => useCatalogPolling({ enabled: true, onCatalogRevisionsChanged: onChanged }));
    await act(async () => {
      await flushPromises();
    });

    await act(async () => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS);
      await flushPromises();
    });
    expect(onChanged).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS);
      await flushPromises();
    });
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it('retries after a failed seed without triggering a refresh', async () => {
    mockFetchSequence([
      new Error('network down'),
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
    ]);
    const onChanged = vi.fn();

    renderHook(() => useCatalogPolling({ enabled: true, onCatalogRevisionsChanged: onChanged }));
    await act(async () => {
      await flushPromises();
    });

    await act(async () => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS);
      await flushPromises();
    });

    expect(onChanged).not.toHaveBeenCalled();
    expect(mocks.fetchQuery).toHaveBeenCalledTimes(2);
  });

  it('pauses polling while hidden and performs an immediate check when visible again', async () => {
    mockFetchSequence([
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
    ]);

    renderHook(() => useCatalogPolling({ enabled: true, onCatalogRevisionsChanged: vi.fn() }));
    await act(async () => {
      await flushPromises();
    });
    expect(mocks.fetchQuery).toHaveBeenCalledTimes(1);

    await act(async () => {
      setDocumentHidden(true);
      document.dispatchEvent(new Event('visibilitychange'));
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS * 2);
      await flushPromises();
    });
    expect(mocks.fetchQuery).toHaveBeenCalledTimes(1);

    await act(async () => {
      setDocumentHidden(false);
      document.dispatchEvent(new Event('visibilitychange'));
      await flushPromises();
    });
    expect(mocks.fetchQuery).toHaveBeenCalledTimes(2);
  });

  it('stops polling on unmount', async () => {
    mockFetchSequence([
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
      { catalogsRevisions: [{ catalog_id: 'catalog-1', revision: 'rev-1' }] },
    ]);

    const { unmount } = renderHook(() => useCatalogPolling({ enabled: true, onCatalogRevisionsChanged: vi.fn() }));
    await act(async () => {
      await flushPromises();
    });

    unmount();

    await act(async () => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS * 2);
      await flushPromises();
    });

    expect(mocks.fetchQuery).toHaveBeenCalledTimes(1);
  });
});
