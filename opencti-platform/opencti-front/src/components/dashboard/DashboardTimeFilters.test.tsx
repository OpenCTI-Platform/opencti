import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import DashboardTimeFilters from './DashboardTimeFilters';

const inDays = (days: number) => new Date(Date.now() + days * 24 * 3600 * 1000).toISOString();

describe('DashboardTimeFilters', () => {
  it('reports a given date the picker refuses, without waiting for a change', async () => {
    const onInvalidDateChange = vi.fn();
    testRender(
      <DashboardTimeFilters
        config={{ relativeDate: null, startDate: inDays(-30), endDate: inDays(30) }}
        handleDateChange={vi.fn()}
        onInvalidDateChange={onInvalidDateChange}
      />,
    );
    await screen.findAllByLabelText('Start date');
    expect(onInvalidDateChange).toHaveBeenCalledWith('startDate', false);
    expect(onInvalidDateChange).toHaveBeenCalledWith('endDate', true);
  });

  it('reports again when the given date changes', async () => {
    const onInvalidDateChange = vi.fn();
    const handleDateChange = vi.fn();
    const { rerender } = testRender(
      <DashboardTimeFilters
        config={{ relativeDate: null, startDate: inDays(-30), endDate: inDays(30) }}
        handleDateChange={handleDateChange}
        onInvalidDateChange={onInvalidDateChange}
      />,
    );
    await screen.findAllByLabelText('End date');
    onInvalidDateChange.mockClear();
    rerender(
      <DashboardTimeFilters
        config={{ relativeDate: null, startDate: inDays(-30), endDate: inDays(-1) }}
        handleDateChange={handleDateChange}
        onInvalidDateChange={onInvalidDateChange}
      />,
    );
    await vi.waitFor(() => expect(onInvalidDateChange).toHaveBeenCalledWith('endDate', false));
  });
});
