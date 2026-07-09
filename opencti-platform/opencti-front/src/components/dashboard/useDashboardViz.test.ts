import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useDashboardViz from './useDashboardViz';

const loadMocks: Array<ReturnType<typeof vi.fn>> = [];
const disposeMocks: Array<ReturnType<typeof vi.fn>> = [];
let refreshTokenMockValue: number | null = null;

vi.mock('react-relay', async (importOriginal) => {
  const React = await import('react');
  const original = await importOriginal<typeof import('react-relay')>();
  return {
    ...original,
    useQueryLoader: vi.fn(() => {
      const loadRef = React.useRef<ReturnType<typeof vi.fn> | null>(null);
      if (!loadRef.current) {
        loadRef.current = vi.fn();
        loadMocks.push(loadRef.current);
      }
      const disposeRef = React.useRef<ReturnType<typeof vi.fn> | null>(null);
      if (!disposeRef.current) {
        disposeRef.current = vi.fn();
        disposeMocks.push(disposeRef.current);
      }
      return [null, loadRef.current, disposeRef.current] as const;
    }),
  };
});

vi.mock('../../utils/hooks/useAuth', () => ({
  default: () => ({
    schema: {
      filterKeysSchema: new Map(),
    },
  }),
}));

vi.mock('./dashboardVizUtils', () => ({
  resolveDataSelection: vi.fn(({
    dataSelection,
    host,
  }: {
    dataSelection: Array<unknown>;
    host?: { kind?: string; customViewTargetEntityId?: string };
  }) => ({
    resolvedDataSelection: dataSelection,
    isMissingHostEntity: host?.kind === 'custom-view' && !host.customViewTargetEntityId,
    isPreviewMode: false,
  })),
}));

vi.mock('./DashboardRefreshContext', () => ({
  useDashboardRefreshToken: vi.fn(() => refreshTokenMockValue),
  useDashboardSetQueryPending: vi.fn(() => () => {}),
}));

describe('useDashboardViz', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-02T10:00:12.345Z'));
    loadMocks.length = 0;
    disposeMocks.length = 0;
    refreshTokenMockValue = null;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('does not refetch sibling widget when only one widget parameters change', () => {
    const buildQueryVariables = vi.fn((_, __, parameters?: { title?: string | null }) => ({
      title: parameters?.title ?? null,
    }));

    const widgetA1 = renderHook(({ parameters }: { parameters: { title: string } }) => useDashboardViz({
      dataSelection: [],
      perspective: 'entities',
      refreshRate: null,
      query: {} as never,
      config: {},
      parameters,
      buildQueryVariables,
    }), {
      initialProps: { parameters: { title: 'A1' } },
    });

    const widgetA2 = renderHook(({ parameters }: { parameters: { title: string } }) => useDashboardViz({
      dataSelection: [],
      perspective: 'entities',
      refreshRate: null,
      query: {} as never,
      config: {},
      parameters,
      buildQueryVariables,
    }), {
      initialProps: { parameters: { title: 'A2' } },
    });

    expect(loadMocks).toHaveLength(2);
    const [a1Load, a2Load] = loadMocks;
    const a1BaselineCalls = a1Load.mock.calls.length;
    const a2BaselineCalls = a2Load.mock.calls.length;

    act(() => {
      widgetA1.rerender({ parameters: { title: 'A1 updated' } });
    });

    expect(a1Load).toHaveBeenCalledTimes(a1BaselineCalls + 1);
    expect(a2Load).toHaveBeenCalledTimes(a2BaselineCalls);

    widgetA1.unmount();
    widgetA2.unmount();
  });

  it('fetches on mount and then refetches when refresh token increments', () => {
    const buildQueryVariables = vi.fn(() => ({ marker: 'token-refetch' }));

    const hook = renderHook(() => useDashboardViz({
      dataSelection: [],
      perspective: 'entities',
      refreshRate: null,
      query: {} as never,
      config: {},
      parameters: {},
      buildQueryVariables,
    }));

    expect(loadMocks).toHaveLength(1);
    const [loadSpy] = loadMocks;
    const mountCalls = loadSpy.mock.calls.length;
    expect(mountCalls).toBeGreaterThanOrEqual(1);

    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(loadSpy).toHaveBeenCalledTimes(mountCalls);

    refreshTokenMockValue = 1;
    hook.rerender();

    act(() => {
      vi.advanceTimersByTime(1_000);
    });

    expect(loadSpy).toHaveBeenCalledTimes(mountCalls + 1);

    hook.unmount();
  });

  it('does not refetch again when rerendering with the same refresh token', () => {
    const buildQueryVariables = vi.fn(() => ({ marker: 'same-token' }));

    const hook = renderHook(() => useDashboardViz({
      dataSelection: [],
      perspective: 'entities',
      refreshRate: null,
      query: {} as never,
      config: {},
      parameters: {},
      buildQueryVariables,
    }));

    expect(loadMocks).toHaveLength(1);
    const [loadSpy] = loadMocks;
    const baselineCalls = loadSpy.mock.calls.length;

    refreshTokenMockValue = 1;
    hook.rerender();
    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(loadSpy).toHaveBeenCalledTimes(baselineCalls + 1);

    hook.rerender();
    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(loadSpy).toHaveBeenCalledTimes(baselineCalls + 1);

    hook.unmount();
  });

  it('does not run widget interval refresh when dashboard token provider is present', () => {
    const buildQueryVariables = vi.fn(() => ({ marker: 'token-disables-interval' }));
    refreshTokenMockValue = 0;

    renderHook(() => useDashboardViz({
      dataSelection: [],
      perspective: 'entities',
      refreshRate: 5_000,
      query: {} as never,
      config: {},
      parameters: {},
      buildQueryVariables,
    }));

    expect(loadMocks).toHaveLength(1);
    const [loadSpy] = loadMocks;
    const mountCalls = loadSpy.mock.calls.length;

    act(() => {
      vi.advanceTimersByTime(5_000);
    });

    expect(loadSpy).toHaveBeenCalledTimes(mountCalls);
  });

  it('keeps workspace host behavior unchanged by missing-host guard', () => {
    const buildQueryVariables = vi.fn(() => ({ marker: 'workspace-host' }));

    const hook = renderHook(() => useDashboardViz({
      dataSelection: [],
      perspective: 'entities',
      host: { kind: 'workspace' },
      refreshRate: null,
      query: {} as never,
      config: {},
      parameters: {},
      buildQueryVariables,
    }));

    expect(loadMocks).toHaveLength(1);
    expect(disposeMocks).toHaveLength(1);
    const [loadSpy] = loadMocks;
    const [disposeSpy] = disposeMocks;

    const mountCalls = loadSpy.mock.calls.length;
    expect(mountCalls).toBeGreaterThanOrEqual(1);
    expect(disposeSpy).not.toHaveBeenCalled();

    refreshTokenMockValue = 1;
    hook.rerender();

    act(() => {
      vi.advanceTimersByTime(1_000);
    });

    expect(loadSpy).toHaveBeenCalledTimes(mountCalls + 1);
    expect(disposeSpy).not.toHaveBeenCalled();

    hook.unmount();
  });
});
