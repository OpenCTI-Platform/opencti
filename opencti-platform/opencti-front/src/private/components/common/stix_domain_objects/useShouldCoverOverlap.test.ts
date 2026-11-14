import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import useShouldCoverOverlap from './useShouldCoverOverlap';

const mockFetchQuery = vi.fn();

vi.mock('../../../../relay/environment', () => ({
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
}));

const toPage = (ids: string[], hasNextPage: boolean, endCursor: string | null = null) => ({
  stixCoreObjects: {
    edges: ids.map((id) => ({ node: { id } })),
    pageInfo: { endCursor, hasNextPage },
  },
});

const mockPages = (...pages: ReturnType<typeof toPage>[]) => {
  pages.forEach((page) => {
    mockFetchQuery.mockReturnValueOnce({ toPromise: () => Promise.resolve(page) });
  });
};

const makeIds = (prefix: string, count: number) => Array.from({ length: count }, (_, i) => `${prefix}-${i}`);

describe('useShouldCoverOverlap', () => {
  beforeEach(() => {
    mockFetchQuery.mockReset();
  });

  it('starts with undefined ids and no error', () => {
    const { result } = renderHook(() => useShouldCoverOverlap());
    expect(result.current.attackPatternIdsToOverlap).toBeUndefined();
    expect(result.current.error).toBeNull();
  });

  it('pages through all results using the end cursor', async () => {
    const firstPage = makeIds('a', 500);
    const secondPage = makeIds('b', 3);
    mockPages(toPage(firstPage, true, 'cursor-1'), toPage(secondPage, false, 'cursor-2'));

    const { result } = renderHook(() => useShouldCoverOverlap());
    await act(async () => {
      await result.current.setSecurityPlatformIds(['platform-1']);
    });

    expect(result.current.attackPatternIdsToOverlap).toEqual([...firstPage, ...secondPage]);
    expect(result.current.attackPatternIdsToOverlap).toHaveLength(503);
    expect(result.current.error).toBeNull();
    expect(mockFetchQuery).toHaveBeenCalledTimes(2);
    expect(mockFetchQuery.mock.calls[0][1]).toMatchObject({ first: 500 });
    expect(mockFetchQuery.mock.calls[0][1].after).toBeUndefined();
    expect(mockFetchQuery.mock.calls[1][1]).toMatchObject({ first: 500, after: 'cursor-1' });
  });

  it('sends the should-cover filters for the given platforms', async () => {
    mockPages(toPage(['ap-1'], false));

    const { result } = renderHook(() => useShouldCoverOverlap());
    await act(async () => {
      await result.current.setSecurityPlatformIds(['platform-1', 'platform-2']);
    });

    expect(mockFetchQuery.mock.calls[0][1]).toMatchObject({
      filters: {
        mode: 'and',
        filters: [
          { key: 'entity_type', operator: 'eq', mode: 'or', values: ['Attack-Pattern'] },
          {
            key: 'regardingOf',
            operator: 'eq',
            mode: 'and',
            values: [
              { key: 'id', values: ['platform-1', 'platform-2'], operator: 'eq', mode: 'or' },
              { key: 'relationship_type', values: ['should-cover'], operator: 'eq', mode: 'or' },
            ],
          },
        ],
        filterGroups: [],
      },
    });
  });

  it('makes no call and gives an empty list when no platform is selected', async () => {
    const { result } = renderHook(() => useShouldCoverOverlap());
    await act(async () => {
      await result.current.setSecurityPlatformIds([]);
    });

    expect(mockFetchQuery).not.toHaveBeenCalled();
    expect(result.current.attackPatternIdsToOverlap).toEqual([]);
    expect(result.current.error).toBeNull();
  });

  it('sets the error and leaves ids undefined when a fetch is rejected', async () => {
    const failure = new Error('network down');
    mockFetchQuery.mockReturnValueOnce({ toPromise: () => Promise.reject(failure) });

    const { result } = renderHook(() => useShouldCoverOverlap());
    await act(async () => {
      await result.current.setSecurityPlatformIds(['platform-1']);
    });

    expect(result.current.error).toBe(failure);
    expect(result.current.attackPatternIdsToOverlap).toBeUndefined();
  });

  it('clears a previous error on the next successful call', async () => {
    mockFetchQuery.mockReturnValueOnce({ toPromise: () => Promise.reject(new Error('boom')) });
    mockPages(toPage(['ap-1'], false));

    const { result } = renderHook(() => useShouldCoverOverlap());
    await act(async () => {
      await result.current.setSecurityPlatformIds(['platform-1']);
    });
    expect(result.current.error).not.toBeNull();

    await act(async () => {
      await result.current.setSecurityPlatformIds(['platform-1']);
    });
    expect(result.current.error).toBeNull();
    expect(result.current.attackPatternIdsToOverlap).toEqual(['ap-1']);
  });

  it('ignores a stale response that resolves after a newer call', async () => {
    let resolveOld: (value: unknown) => void = () => {};
    mockFetchQuery.mockReturnValueOnce({
      toPromise: () => new Promise((resolve) => {
        resolveOld = resolve;
      }),
    });
    mockPages(toPage(['new-ap'], false));

    const { result } = renderHook(() => useShouldCoverOverlap());
    let oldCall: Promise<void> = Promise.resolve();
    act(() => {
      oldCall = result.current.setSecurityPlatformIds(['old-platform']);
    });
    await act(async () => {
      await result.current.setSecurityPlatformIds(['new-platform']);
    });
    expect(result.current.attackPatternIdsToOverlap).toEqual(['new-ap']);

    await act(async () => {
      resolveOld(toPage(['old-ap'], false));
      await oldCall;
    });
    expect(result.current.attackPatternIdsToOverlap).toEqual(['new-ap']);
  });

  it('ignores a stale response when the selection is cleared meanwhile', async () => {
    let resolveOld: (value: unknown) => void = () => {};
    mockFetchQuery.mockReturnValueOnce({
      toPromise: () => new Promise((resolve) => {
        resolveOld = resolve;
      }),
    });

    const { result } = renderHook(() => useShouldCoverOverlap());
    let oldCall: Promise<void> = Promise.resolve();
    act(() => {
      oldCall = result.current.setSecurityPlatformIds(['old-platform']);
    });
    await act(async () => {
      await result.current.setSecurityPlatformIds([]);
    });
    await act(async () => {
      resolveOld(toPage(['old-ap'], false));
      await oldCall;
    });
    expect(result.current.attackPatternIdsToOverlap).toEqual([]);
  });
});
