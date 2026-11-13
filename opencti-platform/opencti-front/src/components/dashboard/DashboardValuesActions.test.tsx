import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';
import DashboardValuesActions from './DashboardValuesActions';

describe('DashboardValuesActions', () => {
  it('renders Reset only when the defaults cannot be set', () => {
    testRender(<DashboardValuesActions canSetAsDefaults={false} onReset={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Reset' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set as default values' })).not.toBeInTheDocument();
  });

  it('keeps both buttons out of the image export', () => {
    testRender(<DashboardValuesActions canSetAsDefaults onReset={vi.fn()} onSetAsDefaults={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Reset' })).toHaveClass(EXPORT_REMOVE_CLASS);
    expect(screen.getByRole('button', { name: 'Set as default values' })).toHaveClass(EXPORT_REMOVE_CLASS);
  });
});
