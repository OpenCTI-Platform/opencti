import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntIocFilterTake from './HuntIocFilterTake';

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
