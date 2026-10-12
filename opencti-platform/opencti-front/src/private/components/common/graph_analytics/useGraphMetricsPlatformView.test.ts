import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useGraphMetricsPlatformView, { isGraphMetricsSortKey } from './useGraphMetricsPlatformView';

const authState = { filterKeys: new Map<string, Map<string, unknown>>() };

vi.mock('../../../../utils/hooks/useAuth', () => ({
  default: () => ({ schema: { filterKeysSchema: authState.filterKeys } }),
}));

describe('useGraphMetricsPlatformView', () => {
  it('detects the sort keys based on the stored graph metrics', () => {
    expect(isGraphMetricsSortKey('graph_degree')).toBe(true);
    expect(isGraphMetricsSortKey('graph_betweenness')).toBe(true);
    expect(isGraphMetricsSortKey('graph_cluster_size')).toBe(true);
    expect(isGraphMetricsSortKey('created_at')).toBe(false);
    expect(isGraphMetricsSortKey(null)).toBe(false);
    expect(isGraphMetricsSortKey(undefined)).toBe(false);
  });

  it('grants the platform view when the graph degree filter key is offered', () => {
    authState.filterKeys = new Map([['Stix-Core-Object', new Map([['graph_degree', {}]])]]);
    const { result } = renderHook(() => useGraphMetricsPlatformView());
    expect(result.current).toBe(true);
  });

  it('withholds the platform view when the graph degree filter key is not offered', () => {
    authState.filterKeys = new Map([['Stix-Core-Object', new Map([['graph_cluster_id', {}]])]]);
    const { result } = renderHook(() => useGraphMetricsPlatformView());
    expect(result.current).toBe(false);
    authState.filterKeys = new Map();
    const { result: empty } = renderHook(() => useGraphMetricsPlatformView());
    expect(empty.current).toBe(false);
  });
});
