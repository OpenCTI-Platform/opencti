import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import PublicDashboardHeader from './PublicDashboardHeader';

const renderHeader = (props: Partial<React.ComponentProps<typeof PublicDashboardHeader>> = {}) => testRender(
  <PublicDashboardHeader
    title="Public view"
    manifestConfig={{ startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null }}
    onChangeRelativeDate={vi.fn()}
    onChangeStartDate={vi.fn()}
    onChangeEndDate={vi.fn()}
    {...props}
  />,
);

// The date picker labels both its hidden input and its field group: the input carries the disabled state
const startDateInput = () => screen.getAllByLabelText('Start date').find((element) => element.tagName === 'INPUT');

describe('PublicDashboardHeader', () => {
  it('should show the published range with disabled time filters by default', () => {
    renderHeader();
    expect(startDateInput()).toBeDisabled();
    expect(screen.queryByTestId('public-dashboard-reset-range')).toBeNull();
  });

  it('should enable the time filters when the author allowed viewers to edit them', () => {
    renderHeader({ editable: true });
    expect(startDateInput()).toBeEnabled();
  });

  it('should offer to go back to the published range once the visitor changed it', async () => {
    const onReset = vi.fn();
    const { user } = renderHeader({ editable: true, onReset });
    await user.click(screen.getByTestId('public-dashboard-reset-range'));
    expect(onReset).toHaveBeenCalledTimes(1);
  });
});
