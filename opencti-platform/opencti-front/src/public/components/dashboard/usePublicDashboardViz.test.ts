import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import usePublicDashboardViz from './usePublicDashboardViz';

const loadMocks: Array<ReturnType<typeof vi.fn>> = [];
let refreshTokenMockValue: number | null = null;

vi.mock('react-relay', async (importOriginal) => {
  const React = await import('react');
  const original = await importOriginal<typeof import('react-relay')>();

  return {
    ...original,
    useQueryLoader: vi.fn(() => {
      const queryRef = React.useRef({ id: 'stable-query-ref' });
      const loadRef = React.useRef<ReturnType<typeof vi.fn> | null>(null);

      if (!loadRef.current) {
        loadRef.current = vi.fn();
        loadMocks.push(loadRef.current);
      }

      return [queryRef.current, loadRef.current] as const;
    }),
  };
});

vi.mock('../../../components/dashboard/DashboardRefreshContext', () => ({
  useDashboardRefreshToken: vi.fn(() => refreshTokenMockValue),
}));

describe('usePublicDashboardViz', () => {
  beforeEach(() => {
    loadMocks.length = 0;
    refreshTokenMockValue = null;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('refetches on refresh token change without clearing queryRef (no loader flash)', async () => {
    const hook = renderHook(() => usePublicDashboardViz(
      {} as never,
      { marker: 'public-refresh' } as never,
    ));

    expect(loadMocks).toHaveLength(1);
    const [loadSpy] = loadMocks;

    await waitFor(() => {
      expect(loadSpy).toHaveBeenCalledTimes(1);
    });

    const stableQueryRef = hook.result.current;
    expect(stableQueryRef).not.toBeNull();

    act(() => {
      refreshTokenMockValue = 1;
      hook.rerender();
    });

    await waitFor(() => {
      expect(loadSpy).toHaveBeenCalledTimes(2);
    });

    expect(hook.result.current).toBe(stableQueryRef);
  });
});
