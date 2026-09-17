import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import RelativeDateInput from './RelativeDateInput';
import { handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

const makeHelpers = (): handleFilterHelpers => ({
  handleReplaceFilterValues: vi.fn(),
} as unknown as handleFilterHelpers);

describe('Component: RelativeDateInput', () => {
  it('does not commit via handleReplaceFilterValues when only one field of the pair is valid', async () => {
    const helpers = makeHelpers();
    const dateInput = ['', ''];
    const setDateInput = vi.fn();

    const { user } = testRender(
      <RelativeDateInput
        filterKey="created_at"
        helpers={helpers}
        label="From"
        valueOrder={0}
        dateInput={dateInput}
        setDateInput={setDateInput}
        autoFocus
      />,
    );

    const input = screen.getByLabelText('From');
    await user.type(input, 'now-7d');
    await user.keyboard('{Enter}');

    expect(helpers.handleReplaceFilterValues).not.toHaveBeenCalled();
  });

  it('commits via handleReplaceFilterValues with the correct values array once both fields are valid', async () => {
    const helpers = makeHelpers();
    const dateInput = ['now-7d', ''];
    const setDateInput = vi.fn();

    const { user } = testRender(
      <RelativeDateInput
        filterKey="created_at"
        helpers={helpers}
        label="To"
        valueOrder={1}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />,
    );

    const input = screen.getByLabelText('To');
    await user.type(input, 'now');
    await user.keyboard('{Enter}');

    expect(helpers.handleReplaceFilterValues).toHaveBeenCalledWith('', ['now-7d', 'now']);
  });

  it('displays a valid absolute date value locale-formatted (not the raw ISO string) while not focused', () => {
    const helpers = makeHelpers();
    const isoValue = '2024-01-15T00:00:00.000Z';
    const dateInput = [isoValue, 'now'];
    const setDateInput = vi.fn();

    testRender(
      <RelativeDateInput
        filterKey="created_at"
        helpers={helpers}
        label="From"
        valueOrder={0}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />,
    );

    const input = screen.getByLabelText('From') as HTMLInputElement;
    expect(input.value).not.toEqual(isoValue);
    expect(input.value.length).toBeGreaterThan(0);
  });

  it('renders exactly one visible textbox and opens the calendar popover from its icon (regression: no duplicate/hidden field)', async () => {
    const helpers = makeHelpers();
    const dateInput = ['', 'now'];
    const setDateInput = vi.fn();

    const { user } = testRender(
      <RelativeDateInput
        filterKey="created_at"
        helpers={helpers}
        label="From"
        valueOrder={0}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />,
    );

    expect(screen.getAllByRole('textbox')).toHaveLength(1);
    expect(screen.queryByRole('grid')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /open date picker/i }));

    expect(screen.getByRole('grid')).toBeInTheDocument();
  });

  it('does not show the relative-date shortcuts icon by default (showShortcuts=false)', () => {
    const helpers = makeHelpers();
    const dateInput = ['', 'now'];
    const setDateInput = vi.fn();

    testRender(
      <RelativeDateInput
        filterKey="created_at"
        helpers={helpers}
        label="From"
        valueOrder={0}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />,
    );

    expect(screen.queryByRole('button', { name: /relative date shortcuts/i })).not.toBeInTheDocument();
  });

  it('shows the relative-date shortcuts icon when showShortcuts=true and commits the selected value', async () => {
    const helpers = makeHelpers();
    const dateInput = ['', 'now'];
    const setDateInput = vi.fn();

    const { user } = testRender(
      <RelativeDateInput
        filterKey="created_at"
        helpers={helpers}
        label="From"
        valueOrder={0}
        dateInput={dateInput}
        setDateInput={setDateInput}
        showShortcuts
      />,
    );

    await user.click(screen.getByRole('button', { name: /relative date shortcuts/i }));
    await user.click(screen.getByText('Last 1 day'));

    expect(helpers.handleReplaceFilterValues).toHaveBeenCalledWith('', ['now-1d', 'now']);
  });
});
