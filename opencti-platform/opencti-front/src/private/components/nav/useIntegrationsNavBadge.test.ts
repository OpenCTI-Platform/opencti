import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CATALOG_POLLING_INTERVAL_MS } from '../integrations/catalog/catalog-constants';
import useIntegrationsNavBadge, { useIntegrationsNavBadgeQueryRef } from './useIntegrationsNavBadge';

const mocks = vi.hoisted(() => ({
  fetchQuery: vi.fn(),
  usePreloadedQuery: vi.fn(),
  useQueryLoader: vi.fn(),
  loadQuery: vi.fn(),
  useGranted: vi.fn(),
}));

vi.mock('../../../relay/environment', () => ({
  fetchQuery: mocks.fetchQuery,
}));

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  usePreloadedQuery: mocks.usePreloadedQuery,
  useQueryLoader: mocks.useQueryLoader,
}));

vi.mock('../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useGranted')>()),
  default: mocks.useGranted,
}));

vi.mock('../../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (message: string, options?: { values?: { count?: number } }) => message.replace('{count}', String(options?.values?.count)),
  }),
}));

const queryRef = { kind: 'PreloadedQuery' } as never;

const setDocumentHidden = (hidden: boolean) => {
  Object.defineProperty(document, 'hidden', {
    configurable: true,
    get: () => hidden,
  });
};

describe('useIntegrationsNavBadge', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    setDocumentHidden(false);
    mocks.useGranted.mockReturnValue(true);
    mocks.usePreloadedQuery.mockReturnValue({
      connectors: [{ update_available: true }, { update_available: false }, { update_available: true }],
    });
    mocks.useQueryLoader.mockReturnValue([queryRef, mocks.loadQuery]);
    mocks.fetchQuery.mockReturnValue({ toPromise: () => Promise.resolve({}) });
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
    setDocumentHidden(false);
  });

  it('should count the connectors with an available update', () => {
    const { result } = renderHook(() => useIntegrationsNavBadge(queryRef));

    expect(result.current).toEqual({ content: 2, accessibleText: '2 connector update available' });
    expect(mocks.usePreloadedQuery).toHaveBeenCalledWith(expect.anything(), queryRef);
  });

  it('should not show a badge when no connector has an available update', () => {
    mocks.usePreloadedQuery.mockReturnValue({ connectors: [{ update_available: false }] });

    const { result } = renderHook(() => useIntegrationsNavBadge(queryRef));

    expect(result.current).toBeUndefined();
  });

  it('should refresh the badge at the catalog polling interval while the tab is visible', () => {
    renderHook(() => useIntegrationsNavBadge(queryRef));
    expect(mocks.fetchQuery).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS);
    });
    expect(mocks.fetchQuery).toHaveBeenCalledTimes(1);
    expect(mocks.fetchQuery).toHaveBeenCalledWith(expect.anything(), {}, { fetchPolicy: 'network-only' });

    setDocumentHidden(true);
    act(() => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS);
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(mocks.fetchQuery).toHaveBeenCalledTimes(1);

    // Back to the tab: refreshed right away, not at the next interval
    setDocumentHidden(false);
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(mocks.fetchQuery).toHaveBeenCalledTimes(2);
  });

  it('should stop refreshing once unmounted', () => {
    const { unmount } = renderHook(() => useIntegrationsNavBadge(queryRef));
    unmount();

    act(() => {
      vi.advanceTimersByTime(CATALOG_POLLING_INTERVAL_MS * 2);
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(mocks.fetchQuery).not.toHaveBeenCalled();
  });

  it('should load the statuses with the navigation when the user can read connectors', () => {
    const { result } = renderHook(() => useIntegrationsNavBadgeQueryRef());

    expect(result.current).toBe(queryRef);
    expect(mocks.loadQuery).toHaveBeenCalledWith({}, { fetchPolicy: 'store-and-network' });
  });

  it('should neither load nor show a badge without the capability to read connectors', () => {
    mocks.useGranted.mockReturnValue(false);

    const { result } = renderHook(() => useIntegrationsNavBadgeQueryRef());

    expect(result.current).toBeNull();
    expect(mocks.loadQuery).not.toHaveBeenCalled();
  });
});
