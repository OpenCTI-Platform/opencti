import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import PublicDashboardHeader from './PublicDashboardHeader';

// The date picker labels both its hidden input and its field group: the input carries the disabled state
const dateInput = (label: string) => screen.getAllByLabelText(label).find((element) => element.tagName === 'INPUT');

describe('PublicDashboardHeader', () => {
  it('should show the published range with read only time filters', () => {
    testRender(
      <PublicDashboardHeader
        title="Public view"
        manifestConfig={{ startDate: '2026-01-01T00:00:00.000Z', endDate: null, relativeDate: null }}
        onChangeRelativeDate={vi.fn()}
        onChangeStartDate={vi.fn()}
        onChangeEndDate={vi.fn()}
      />,
    );
    expect(dateInput('Start date')).toBeDisabled();
    expect(dateInput('End date')).toBeDisabled();
    expect(screen.getByRole('combobox')).toHaveAttribute('aria-disabled', 'true');
  });
});
