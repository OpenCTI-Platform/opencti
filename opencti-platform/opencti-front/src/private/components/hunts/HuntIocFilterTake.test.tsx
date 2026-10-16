import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook, screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import HuntIocFilterTake, { useHuntedExclusion } from './HuntIocFilterTake';

const { fetchQueryMock } = vi.hoisted(() => ({ fetchQueryMock: vi.fn() }));

vi.mock('./useHuntConfiguration', () => ({ default: () => ({ maxFilterEntitiesPerRun: 100 }) }));
vi.mock('../../../relay/environment', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../relay/environment')>();
  return { ...original, fetchQuery: fetchQueryMock };
});

const answer = (matching_count: number, taken_count: number) => {
  fetchQueryMock.mockReturnValue({ toPromise: () => Promise.resolve({ hunt: { id: 'hunt-1', iocFilterPreview: { matching_count, taken_count } } }) });
};

const FILTERS = '{"mode":"and","filters":[{"key":"objectLabel","values":["apt28"]}],"filterGroups":[]}';

describe('What a run takes out of the filter of an indicator hunt', () => {
  afterEach(() => vi.clearAllMocks());

  it('counts what the filter as edited matches, in the order chosen, and tells how many the next run takes', async () => {
    answer(2340, 100);
    testRender(<HuntIocFilterTake huntId="hunt-1" filters={FILTERS} sort="updated_at_desc" onSortChange={() => undefined} />);
    expect(screen.getByText('Each run takes at most 100 of them:')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-ioc-sort')).toHaveTextContent('Recently updated first');
    await waitFor(() => expect(screen.getByTestId('hunt-ioc-filter-count'))
      .toHaveTextContent('2,340 indicators and observables match the filter: the next run takes 100 of them, in the order above'));
    expect(fetchQueryMock).toHaveBeenCalledTimes(1);
    expect(fetchQueryMock.mock.calls[0][1]).toEqual({ id: 'hunt-1', filters: FILTERS, sort: 'updated_at_desc' });
  });

  it('says the next run takes every match under the limit, and that nothing the hunt can take matches', async () => {
    answer(40, 40);
    const { unmount } = testRender(<HuntIocFilterTake huntId="hunt-1" filters={FILTERS} sort="created_at_desc" onSortChange={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId('hunt-ioc-filter-count'))
      .toHaveTextContent('40 indicators and observables match the filter: the next run takes them all'));
    unmount();
    answer(0, 0);
    testRender(<HuntIocFilterTake huntId="hunt-1" filters={FILTERS} sort="created_at_desc" onSortChange={() => undefined} />);
    await waitFor(() => expect(screen.getByTestId('hunt-ioc-filter-count'))
      .toHaveTextContent('No indicator or observable the hunt can take matches the filter'));
  });

  it('suggests leaving out the entities hunted since the last run when the filter holds more than a run takes', async () => {
    answer(2340, 100);
    const onExcludeHunted = vi.fn();
    const props = { huntId: 'hunt-1', filters: FILTERS, sort: 'created_at_desc' as const, onSortChange: () => undefined, lastRunAt: '2026-10-15T06:00:00.000Z', onExcludeHunted };
    const { user, unmount } = testRender(<HuntIocFilterTake {...props} />);
    const suggestion = await screen.findByTestId('hunt-ioc-exclude-hunted');
    expect(suggestion).toHaveTextContent(/^Exclude the entities hunted since /);
    await user.click(suggestion);
    expect(onExcludeHunted).toHaveBeenCalledWith('2026-10-15T06:00:00.000Z');
    unmount();
    // Already left out, or every match taken: nothing to suggest
    const { unmount: unmountExcluded } = testRender(<HuntIocFilterTake {...props} huntedExcluded />);
    await screen.findByTestId('hunt-ioc-filter-count');
    expect(screen.queryByTestId('hunt-ioc-exclude-hunted')).not.toBeInTheDocument();
    unmountExcluded();
    answer(40, 40);
    testRender(<HuntIocFilterTake {...props} />);
    await screen.findByTestId('hunt-ioc-filter-count');
    expect(screen.queryByTestId('hunt-ioc-exclude-hunted')).not.toBeInTheDocument();
  });

  it('leaves out the entities hunted since a date in a group of their own, keeping the ones never hunted', async () => {
    const initial = { mode: 'and', filters: [{ key: 'objectLabel', values: ['apt28'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    const { result } = renderHook(() => {
      const filtersState = useFiltersState(initial);
      return { filters: filtersState[0], exclusion: useHuntedExclusion(filtersState) };
    });
    expect(result.current.exclusion.excluded).toBe(false);
    act(() => result.current.exclusion.exclude('2026-10-15T06:00:00.000Z'));
    await waitFor(() => expect(result.current.filters.filterGroups[0]?.filters).toHaveLength(2));
    expect(JSON.parse(serializeFilterGroupForBackend(result.current.filters))).toEqual({
      mode: 'and',
      filters: [{ key: ['objectLabel'], values: ['apt28'], operator: 'eq', mode: 'or' }],
      filterGroups: [{
        mode: 'or',
        filters: [
          { key: ['x_opencti_hunted_at'], values: ['2026-10-15T06:00:00.000Z'], operator: 'lt', mode: 'or' },
          { key: ['x_opencti_hunted_at'], values: [], operator: 'nil', mode: 'or' },
        ],
        filterGroups: [],
      }],
    });
    expect(result.current.exclusion.excluded).toBe(true);
  });

  it('asks nothing while the hunt has no filter', async () => {
    testRender(<HuntIocFilterTake huntId="hunt-1" filters={null} sort="created_at_desc" onSortChange={() => undefined} />);
    expect(screen.getByTestId('hunt-ioc-sort')).toHaveTextContent('Newest created first');
    await new Promise((resolve) => {
      setTimeout(resolve, 500);
    });
    expect(fetchQueryMock).not.toHaveBeenCalled();
    expect(screen.queryByTestId('hunt-ioc-filter-count')).not.toBeInTheDocument();
  });
});
