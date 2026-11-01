import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';
import DashboardWidgetVariablesMarker from './DashboardWidgetVariablesMarker';

describe('DashboardWidgetVariablesMarker', () => {
  it('renders nothing without names', () => {
    testRender(<DashboardWidgetVariablesMarker names={[]} />);
    expect(screen.queryByTestId('widget-variables-marker')).not.toBeInTheDocument();
  });

  it('lists the names in its tooltip', async () => {
    const { user } = testRender(<DashboardWidgetVariablesMarker names={['Sector', 'Topic']} />);
    await user.hover(screen.getByTestId('widget-variables-marker'));
    expect((await screen.findAllByText('Uses variables:')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('Sector').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Topic').length).toBeGreaterThan(0);
  });

  it('is kept out of the image export and out of the widget drag handle', () => {
    testRender(<DashboardWidgetVariablesMarker names={['Sector']} />);
    expect(screen.getByTestId('widget-variables-marker')).toHaveClass(EXPORT_REMOVE_CLASS, 'noDrag');
  });
});
