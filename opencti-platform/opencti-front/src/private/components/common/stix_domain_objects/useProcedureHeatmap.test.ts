import { describe, expect, it, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import useProcedureHeatmap from './useProcedureHeatmap';
import type { StixDomainObjectAttackPatternsProcedureHeatmapQuery$data } from './__generated__/StixDomainObjectAttackPatternsProcedureHeatmapQuery.graphql';

const data = {
  procedures: { edges: [{ node: { id: 'p1', name: 'P1', stixCoreRelationships: { edges: [{ node: { to: { id: 'ap1' } } }] } } }] },
} as unknown as StixDomainObjectAttackPatternsProcedureHeatmapQuery$data;

const deferred = () => {
  let resolve: (value: StixDomainObjectAttackPatternsProcedureHeatmapQuery$data) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  const promise = new Promise<StixDomainObjectAttackPatternsProcedureHeatmapQuery$data>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

describe('useProcedureHeatmap', () => {
  it('loads the usage when turned on and clears it when turned off', async () => {
    const load = vi.fn().mockResolvedValue(data);
    const { result } = renderHook(() => useProcedureHeatmap({ entityId: 'e1', load, onError: vi.fn() }));
    await act(() => result.current.toggle());
    expect(load).toHaveBeenCalledTimes(1);
    expect(result.current.procedureUsage?.get('ap1')?.score).toBe(1);
    await act(() => result.current.toggle());
    expect(result.current.procedureUsage).toBeUndefined();
  });
  it('ignores clicks while loading', async () => {
    const pending = deferred();
    const load = vi.fn().mockReturnValue(pending.promise);
    const { result } = renderHook(() => useProcedureHeatmap({ entityId: 'e1', load, onError: vi.fn() }));
    act(() => {
      result.current.toggle();
    });
    expect(result.current.isLoading).toBe(true);
    act(() => {
      result.current.toggle();
    });
    expect(load).toHaveBeenCalledTimes(1);
    await act(async () => pending.resolve(data));
    expect(result.current.isLoading).toBe(false);
    expect(result.current.procedureUsage).toBeDefined();
  });
  it('stays off and reports the error when loading fails', async () => {
    const pending = deferred();
    const onError = vi.fn();
    const { result } = renderHook(() => useProcedureHeatmap({ entityId: 'e1', load: () => pending.promise, onError }));
    act(() => {
      result.current.toggle();
    });
    await act(async () => pending.reject(new Error('boom')));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.procedureUsage).toBeUndefined();
    expect(onError).toHaveBeenCalledTimes(1);
  });
});
