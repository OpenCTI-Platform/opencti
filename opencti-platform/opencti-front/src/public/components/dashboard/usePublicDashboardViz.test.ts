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
  useDashboardSetQueryPending: vi.fn(() => () => {}),
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

/**
 * Decision D4: public dashboards carry no navigation. The drill-down is
 * excluded structurally rather than by convention -- the public viz hook
 * returns a query reference and nothing else, so a public widget has no
 * descriptor to hand to a chart even by mistake.
 *
 * Reading the source is deliberate: the point is that the word never appears,
 * which no behavioural assertion on the returned value can guarantee.
 */
describe('usePublicDashboardViz drill-down exclusion', () => {
  it('never exposes a drill-down descriptor', async () => {
    const source = (await import('./usePublicDashboardViz?raw')).default;
    expect(source.toLowerCase()).not.toContain('drilldown');
  });
});
