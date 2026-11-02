import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import useDashboardViz from './useDashboardViz';
import { resolveDataSelection } from './dashboardVizUtils';
import { DashboardVariableValuesProvider } from './DashboardVariableValuesContext';
import { WidgetDataSelection, WidgetHost } from 'src/utils/widget/widget';

const loadMocks: Array<ReturnType<typeof vi.fn>> = [];
const disposeMocks: Array<ReturnType<typeof vi.fn>> = [];
let refreshTokenMockValue: number | null = null;
// Resolutions of the selections holding a `deferred` key, run by the test, as a saved filter read from the API
const deferredResolutions: Array<() => void> = [];

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

// The same schema at every render, as the one of the user context: a new one resolves the selection again
const filterKeysSchema = new Map();
vi.mock('../../utils/hooks/useAuth', () => ({
  default: () => ({
    schema: {
      filterKeysSchema,
    },
  }),
}));

// Return a synchronous thenable so that the .then() callback runs
// inside renderHook's act() without requiring async microtask flushing,
// which deadlocks with vitest fake timers.
vi.mock('./dashboardVizUtils', () => ({
  resolveDataSelection: vi.fn(({
    dataSelection,
    host,
  }: {
    dataSelection: Array<unknown>;
    host?: { kind?: string; customViewTargetEntityId?: string };
  }) => {
    const result = {
      resolvedDataSelection: dataSelection,
      isMissingHostEntity: host?.kind === 'custom-view' && !host.customViewTargetEntityId,
      isPreviewMode: false,
      isMissingSavedFilters: false,
      hasUnresolvedVariables: JSON.stringify(dataSelection).includes('$var:'),
    };
    if (JSON.stringify(dataSelection).includes('deferred')) {
      return { then: (cb: (r: typeof result) => void) => deferredResolutions.push(() => cb(result)) };
    }
    return { then: (cb: (r: typeof result) => void) => cb(result) };
  }),
}));

vi.mock('./DashboardRefreshContext', () => ({
  useDashboardRefreshToken: vi.fn(() => refreshTokenMockValue),
  useDashboardSetQueryPending: vi.fn(() => () => {}),
}));

describe('useDashboardViz', () => {
  // Non-empty stable data selection: resolvedDataSelection.length must be > 0
  // for queryVariables to be computed and load() to be called.
  const EMPTY_DATA_SELECTION = [{ filters: null }];

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-02T10:00:12.345Z'));
    loadMocks.length = 0;
    disposeMocks.length = 0;
    deferredResolutions.length = 0;
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
      dataSelection: EMPTY_DATA_SELECTION,
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
      dataSelection: EMPTY_DATA_SELECTION,
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

  it('does not refetch when the widget gets new parameters with the same content (manifest refreshed)', () => {
    const buildQueryVariables = vi.fn((_, __, parameters?: { title?: string | null }) => ({
      title: parameters?.title ?? null,
      // Computed from "now", as a relative range is: a rebuild would change the variables.
      at: Date.now(),
    }));
    // Stable, as the dashboard memoizes it on the range.
    const config = {};
    const widget = renderHook(({ parameters }: { parameters: { title: string } }) => useDashboardViz({
      dataSelection: EMPTY_DATA_SELECTION,
      perspective: 'entities',
      refreshRate: null,
      query: {} as never,
      config,
      parameters,
      buildQueryVariables,
    }), {
      initialProps: { parameters: { title: 'A' } },
    });
    const [load] = loadMocks;
    const baselineCalls = load.mock.calls.length;
    vi.advanceTimersByTime(5000);
    act(() => {
      widget.rerender({ parameters: { title: 'A' } });
    });
    expect(load).toHaveBeenCalledTimes(baselineCalls);
    widget.unmount();
  });

  it('fetches on mount and then refetches when refresh token increments', () => {
    const buildQueryVariables = vi.fn(() => ({ marker: 'token-refetch' }));

    const hook = renderHook(() => useDashboardViz({
      dataSelection: EMPTY_DATA_SELECTION,
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
      dataSelection: EMPTY_DATA_SELECTION,
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
      dataSelection: EMPTY_DATA_SELECTION,
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
      dataSelection: EMPTY_DATA_SELECTION,
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

  it('reloads with the freshly resolved data selection when refresh token changes', () => {
    // resolveDataSelection mock echoes dataSelection into resolvedDataSelection,
    // so buildQueryVariables receives the resolved selection as its first argument.
    const buildQueryVariables = vi.fn((resolvedDataSelection: WidgetDataSelection[]) => ({
      field: resolvedDataSelection[0]?.field?.toUpperCase() ?? null,
    }));

    const hook = renderHook(({ dataSelection }: { dataSelection: WidgetDataSelection[] }) => useDashboardViz({
      dataSelection,
      perspective: 'entities',
      refreshRate: null,
      query: {} as never,
      config: {},
      parameters: {},
      buildQueryVariables,
    }), {
      initialProps: { dataSelection: [{ field: 'selection1' }] },
    });

    const [loadSpy] = loadMocks;

    // The load triggered by the initial call must use the resolved data selection.
    let lastLoadVariables = loadSpy.mock.calls.at(-1)?.[0];
    expect(lastLoadVariables).toEqual({ field: 'SELECTION1' });

    // Change both the data selection and the refresh token in the same rerender.
    refreshTokenMockValue = 2;
    hook.rerender({ dataSelection: [{ field: 'selection2' }] });

    act(() => {
      vi.advanceTimersByTime(1_000);
    });

    // The reload triggered by the refresh token must use the new resolved data selection.
    lastLoadVariables = loadSpy.mock.calls.at(-1)?.[0];
    expect(lastLoadVariables).toEqual({ field: 'SELECTION2' });

    hook.unmount();
  });
  it('disposes the query as soon as one guard blocks the widget', () => {
    renderHook(() => useDashboardViz({
      dataSelection: EMPTY_DATA_SELECTION,
      perspective: 'entities',
      host: { kind: 'custom-view' } as WidgetHost,
      query: {} as never,
    }));
    // isMissingHostEntity alone (no target entity) must be enough to dispose the query
    expect(disposeMocks.at(-1)).toHaveBeenCalled();
  });
  it('does not load the query and exposes the guard when a variable is unresolved', () => {
    const dataSelection = [{ filters: { mode: 'and', filters: [{ key: 'createdBy', values: ['$var:11111111-1111-4111-8111-111111111111'] }], filterGroups: [] } }] as unknown as WidgetDataSelection[];
    const { result } = renderHook(() => useDashboardViz({
      dataSelection,
      perspective: 'entities',
      query: {} as never,
      config: {},
      buildQueryVariables: () => ({}),
    }));
    expect(result.current.renderGuards.hasUnresolvedVariables).toBe(true);
    expect(loadMocks.at(-1)).not.toHaveBeenCalled();
    expect(disposeMocks.at(-1)).toHaveBeenCalled();
  });

  it('queries nothing while the selection is resolved, nor the previous filters with the new parameters', () => {
    const buildQueryVariables = vi.fn((resolvedDataSelection: WidgetDataSelection[], _: unknown, parameters?: { breakdownBy?: string | null }) => ({
      filters: resolvedDataSelection[0]?.filters ?? null,
      field: parameters?.breakdownBy,
    }));
    const initialProps = { dataSelection: [{ filters: 'reports' }] as unknown as WidgetDataSelection[], parameters: { breakdownBy: 'objectLabel' } };
    const hook = renderHook(({ dataSelection, parameters }: typeof initialProps) => useDashboardViz({
      dataSelection,
      perspective: 'entities',
      query: {} as never,
      config: {},
      parameters,
      buildQueryVariables,
    }), { initialProps });
    const [loadSpy] = loadMocks;
    const [disposeSpy] = disposeMocks;
    expect(loadSpy).toHaveBeenCalledTimes(1);
    expect(loadSpy.mock.lastCall?.[0]).toEqual({ filters: 'reports', field: 'objectLabel' });

    // Edited to read a saved filter, still read from the API, with another field: no variables are built until it
    // is read, and the query of the previous filters is not shown
    const builtVariablesCount = buildQueryVariables.mock.calls.length;
    hook.rerender({ dataSelection: [{ filters: 'deferred' }] as unknown as WidgetDataSelection[], parameters: { breakdownBy: 'objectAssignee' } });
    expect(buildQueryVariables).toHaveBeenCalledTimes(builtVariablesCount);
    expect(loadSpy).toHaveBeenCalledTimes(1);
    expect(buildQueryVariables).not.toHaveBeenCalledWith([{ filters: 'reports' }], {}, { breakdownBy: 'objectAssignee' });
    expect(disposeSpy).toHaveBeenCalledTimes(1);

    act(() => deferredResolutions.shift()?.());
    expect(loadSpy).toHaveBeenCalledTimes(2);
    expect(loadSpy.mock.lastCall?.[0]).toEqual({ filters: 'deferred', field: 'objectAssignee' });
    hook.unmount();
  });

  it('keeps the selection resolved on a refresh, which resolves the same selection again', () => {
    const buildQueryVariables = vi.fn(() => ({ marker: 'refresh-resolution' }));
    const hook = renderHook(() => useDashboardViz({
      dataSelection: [{ filters: 'deferred' }] as unknown as WidgetDataSelection[],
      perspective: 'entities',
      query: {} as never,
      config: {},
      parameters: {},
      buildQueryVariables,
    }));
    const [loadSpy] = loadMocks;
    const [disposeSpy] = disposeMocks;
    // Nothing is queried until the selection is resolved
    expect(buildQueryVariables).not.toHaveBeenCalled();
    expect(loadSpy).not.toHaveBeenCalled();
    act(() => deferredResolutions.shift()?.());
    expect(loadSpy).toHaveBeenCalledTimes(1);

    // While the refresh resolves it again, the query loaded is still shown
    refreshTokenMockValue = 1;
    hook.rerender();
    expect(disposeSpy).not.toHaveBeenCalled();
    act(() => deferredResolutions.shift()?.());
    expect(loadSpy).toHaveBeenCalledTimes(2);
    expect(disposeSpy).not.toHaveBeenCalled();
    hook.unmount();
  });

  it('passes the context variable values to the resolution', () => {
    const values = new Map([['11111111-1111-4111-8111-111111111111', 'org-id']]);
    renderHook(() => useDashboardViz({ dataSelection: EMPTY_DATA_SELECTION, perspective: 'entities', query: {} as never }), {
      wrapper: ({ children }) => createElement(DashboardVariableValuesProvider, { values }, children),
    });
    expect(vi.mocked(resolveDataSelection)).toHaveBeenLastCalledWith(expect.objectContaining({ variableValues: values }));
  });

  it('passes the context date variable ids to the resolution, for the day shift of lte and gt', () => {
    const values = new Map([['11111111-1111-4111-8111-111111111111', '2024-01-15T00:00:00.000Z']]);
    const dateVariableIds = new Set(['11111111-1111-4111-8111-111111111111']);
    renderHook(() => useDashboardViz({ dataSelection: EMPTY_DATA_SELECTION, perspective: 'entities', query: {} as never }), {
      wrapper: ({ children }) => createElement(DashboardVariableValuesProvider, { values, dateVariableIds }, children),
    });
    expect(vi.mocked(resolveDataSelection)).toHaveBeenLastCalledWith(expect.objectContaining({ variableValues: values, dateVariableIds }));
  });
});
