import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import DateRangeFilter from './DateRangeFilter';
import { handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

const makeHelpers = (): handleFilterHelpers => ({
  handleReplaceFilterValues: vi.fn(),
} as unknown as handleFilterHelpers);

describe('Component: DateRangeFilter', () => {
  it('shows a compact textual summary instead of the fields when showRelativeDateShortcuts is set (nested-group row)', () => {
    const helpers = makeHelpers();

    testRender(
      <DateRangeFilter
        filterKey="created_at"
        helpers={helpers}
        filterValues={['now-7d', 'now']}
        showRelativeDateShortcuts
      />,
    );

    expect(screen.queryByLabelText('From')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('To')).not.toBeInTheDocument();
    expect(screen.getByText(/last 7 days/i)).toBeInTheDocument();
  });

  it('opens a popover with both fields and the quick shortcuts when the summary is clicked', async () => {
    const helpers = makeHelpers();

    const { user } = testRender(
      <DateRangeFilter
        filterKey="created_at"
        helpers={helpers}
        filterValues={['now-7d', 'now']}
        showRelativeDateShortcuts
      />,
    );

    await user.click(screen.getByText(/last 7 days/i));

    expect(screen.getByLabelText('From')).toBeInTheDocument();
    expect(screen.getByLabelText('To')).toBeInTheDocument();
    expect(screen.getByText('Last 1 day')).toBeInTheDocument();
  });

  it('renders the fields directly inline, with no summary and no shortcuts of its own, when showRelativeDateShortcuts is not set (root chip popover adds its own shortcuts column)', () => {
    const helpers = makeHelpers();

    testRender(
      <DateRangeFilter
        filterKey="created_at"
        helpers={helpers}
        filterValues={['now-7d', 'now']}
      />,
    );

    expect(screen.getByLabelText('From')).toBeInTheDocument();
    expect(screen.getByLabelText('To')).toBeInTheDocument();
    expect(screen.queryByText('Last 1 day')).not.toBeInTheDocument();
  });
});
