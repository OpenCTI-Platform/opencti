import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useWidgetDrilldown from './useWidgetDrilldown';

// The real `useAuth` serves a stable context value; a factory-scoped constant
// reproduces that, otherwise a fresh schema each render would defeat memoization.
vi.mock('../../hooks/useAuth', () => {
  const schema = { filterKeysSchema: new Map(), scrs: [{ id: 'targets', label: 'targets' }] };
  return { default: () => ({ schema }) };
});

const selection = {
  perspective: 'entities',
  date_attribute: 'created_at',
  filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] },
};

const NO_RANGE = { startDate: null, endDate: null };

describe('useWidgetDrilldown', () => {
  it('resolves a link for a known selection index', () => {
    const { result } = renderHook(() => useWidgetDrilldown({
      perspective: 'entities',
      resolvedDataSelection: [selection] as never,
      range: NO_RANGE,
      configRange: NO_RANGE,
      interval: 'month',
    }));
    const link = result.current.getLink(0, { kind: 'timeSeries', date: '2024-03-01T00:00:00.000Z' });
    expect(link).toContain('/dashboard/arsenal/malwares?filters=');
  });

  it('returns null for an out-of-range selection index', () => {
    const { result } = renderHook(() => useWidgetDrilldown({
      perspective: 'entities',
      resolvedDataSelection: [selection] as never,
      range: NO_RANGE,
      configRange: NO_RANGE,
      interval: 'month',
    }));
    expect(result.current.getLink(3, { kind: 'timeSeries', date: '2024-03-01T00:00:00.000Z' })).toBeNull();
  });

  it('clamps with the range it was given', () => {
    const { result } = renderHook(() => useWidgetDrilldown({
      perspective: 'entities',
      resolvedDataSelection: [selection] as never,
      range: { startDate: '2024-03-10T00:00:00.000Z', endDate: null },
      configRange: NO_RANGE,
      interval: 'month',
    }));
    const link = result.current.getLink(0, { kind: 'timeSeries', date: '2024-03-01T00:00:00.000Z' }) as string;
    expect(decodeURIComponent(link)).toContain('2024-03-10T00:00:00.000Z');
  });

  it('keeps a stable getLink identity across re-renders with equal inputs', () => {
    const props = {
      perspective: 'entities' as const,
      resolvedDataSelection: [selection] as never,
      range: NO_RANGE,
      configRange: NO_RANGE,
      interval: 'month',
    };
    const { result, rerender } = renderHook(() => useWidgetDrilldown(props));
    const first = result.current.getLink;
    rerender();
    expect(result.current.getLink).toBe(first);
  });
});
