import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import fetchMetaObjectsCount from './fetchMetaObjectsCount';
import useInvestigationObjects, { InvestigationObjectsData } from './useInvestigationObjects';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

vi.mock('./fetchMetaObjectsCount', () => ({ default: vi.fn() }));

const workspace = (...ids: string[]) => ({
  objects: { edges: ids.map((id) => ({ types: [], node: { id, parent_types: [] } })) },
}) as unknown as InvestigationObjectsData;

const deferred = () => {
  let resolve: (objects: ObjectToParse[]) => void = () => {};
  let reject: (error: Error) => void = () => {};
  const promise = new Promise<ObjectToParse[]>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const ids = (objects: ObjectToParse[]) => objects.map(({ id }) => id);

describe('useInvestigationObjects', () => {
  afterEach(() => {
    vi.mocked(fetchMetaObjectsCount).mockReset();
  });

  it('never reports objects as loaded before the matching objects are published', async () => {
    const counts = deferred();
    vi.mocked(fetchMetaObjectsCount).mockReturnValue(counts.promise);

    const data = workspace('a', 'b');
    const { result } = renderHook(() => useInvestigationObjects(data));
    // The page is in, but its objects are not published yet: the count must not move.
    expect(result.current).toEqual({ objects: [], loadedCount: 0 });

    await act(async () => counts.resolve([{ id: 'a' }, { id: 'b' }] as ObjectToParse[]));
    expect(ids(result.current.objects)).toEqual(['a', 'b']);
    expect(result.current.loadedCount).toBe(2);
  });

  it('ignores an older lookup that resolves after a newer one', async () => {
    const firstPage = deferred();
    const secondPage = deferred();
    vi.mocked(fetchMetaObjectsCount)
      .mockReturnValueOnce(firstPage.promise)
      .mockReturnValueOnce(secondPage.promise);

    const { result, rerender } = renderHook(({ data }) => useInvestigationObjects(data), {
      initialProps: { data: workspace('a') },
    });
    rerender({ data: workspace('a', 'b') });

    await act(async () => secondPage.resolve([{ id: 'a' }, { id: 'b' }] as ObjectToParse[]));
    await act(async () => firstPage.resolve([{ id: 'a' }] as ObjectToParse[]));

    expect(ids(result.current.objects)).toEqual(['a', 'b']);
    expect(result.current.loadedCount).toBe(2);
  });

  it('publishes the objects without counts when the count lookup fails', async () => {
    const counts = deferred();
    vi.mocked(fetchMetaObjectsCount).mockReturnValue(counts.promise);

    const data = workspace('a');
    const { result } = renderHook(() => useInvestigationObjects(data));
    await act(async () => counts.reject(new Error('network')));

    expect(ids(result.current.objects)).toEqual(['a']);
    expect(result.current.loadedCount).toBe(1);
  });
});
