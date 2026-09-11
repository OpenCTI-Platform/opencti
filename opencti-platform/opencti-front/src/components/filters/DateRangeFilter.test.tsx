import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import DateRangeFilter from './DateRangeFilter';
import { handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

const makeHelpers = (): handleFilterHelpers => ({
  handleReplaceFilterValues: vi.fn(),
} as unknown as handleFilterHelpers);

describe('Component: DateRangeFilter', () => {
  it('shows the relative-date shortcuts icon only on the From field, not the To field', () => {
    const helpers = makeHelpers();

    testRender(
      <DateRangeFilter
        filterKey="created_at"
        helpers={helpers}
        filterValues={['now-7d', 'now']}
        showRelativeDateShortcuts
      />,
    );

    expect(screen.getAllByRole('button', { name: /relative date shortcuts/i })).toHaveLength(1);
  });

  it('does not show the relative-date shortcuts icon on either field when showRelativeDateShortcuts is not set', () => {
    const helpers = makeHelpers();

    testRender(
      <DateRangeFilter
        filterKey="created_at"
        helpers={helpers}
        filterValues={['now-7d', 'now']}
      />,
    );

    expect(screen.queryByRole('button', { name: /relative date shortcuts/i })).not.toBeInTheDocument();
  });
});
