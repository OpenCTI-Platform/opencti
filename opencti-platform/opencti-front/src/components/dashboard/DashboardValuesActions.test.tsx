import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';
import DashboardValuesActions from './DashboardValuesActions';

describe('DashboardValuesActions', () => {
  it('names the dashboard defaults when there is no default preset', async () => {
    const onReset = vi.fn();
    const { user } = testRender(<DashboardValuesActions onReset={onReset} />);
    await user.click(screen.getByRole('button', { name: 'Reset to defaults' }));
    expect(onReset).toHaveBeenCalledOnce();
  });

  it('names the default preset it goes back to', () => {
    testRender(<DashboardValuesActions resetTargetName="Finance" onReset={vi.fn()} />);
    expect(screen.getByTestId('dashboard-values-reset')).toHaveTextContent('Reset to “Finance”');
  });

  it('stays out of the image export', () => {
    testRender(<DashboardValuesActions onReset={vi.fn()} />);
    expect(screen.getByTestId('dashboard-values-reset')).toHaveClass(EXPORT_REMOVE_CLASS);
  });
});
