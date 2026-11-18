import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { toB64 } from '../../utils/String';
import DashboardContent from './DashboardContent';
import useDashboard from './useDashboard';
import type { DashboardWidget } from './dashboard-types';

// The grid and the widgets themselves are out of scope: only the header action of each widget is looked at.
vi.mock('react-grid-layout', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="grid">{children}</div>,
  useContainerWidth: () => ({ width: 1200, containerRef: { current: null } }),
}));
vi.mock('./DashboardViz', () => ({
  default: ({ widget, popover }: { widget: DashboardWidget; popover: React.ReactNode }) => (
    <div data-testid={`viz-${widget.id}`}>{popover}</div>
  ),
}));
vi.mock('./DashboardWidgetPopover', () => ({ default: () => <div data-testid="widget-popover" /> }));

const widget = (id: string): DashboardWidget => ({
  id,
  type: 'text',
  perspective: 'entities',
  dataSelection: [],
  layout: { i: id, x: 0, y: 0, w: 4, h: 4, moved: false, static: false },
} as DashboardWidget);

const Host = ({ isEditable, names }: { isEditable: boolean; names?: ReadonlyMap<string, readonly string[]> }) => {
  const entity = { id: 'dashboard-1', manifest: toB64(JSON.stringify({ config: {}, widgets: { 'w-1': widget('w-1'), 'w-2': widget('w-2') } })) };
  const helpers = useDashboard({ entity });
  return <DashboardContent entity={entity} helpers={helpers} host={{ kind: 'workspace' }} isEditable={isEditable} variableNamesByWidget={names} />;
};

describe('DashboardContent', () => {
  it('marks the widgets using variables, for a reader too, and only those', () => {
    testRender(<Host isEditable={false} names={new Map([['w-1', ['Sector']]])} />);
    expect(screen.getByRole('button', { name: 'Uses variables: Sector' })).toBeInTheDocument();
    expect(screen.getAllByTestId('widget-variables-marker')).toHaveLength(1);
    expect(screen.queryByTestId('widget-popover')).not.toBeInTheDocument();
  });

  it('keeps the menu of the editor next to the marker', () => {
    testRender(<Host isEditable names={new Map([['w-1', ['Sector']]])} />);
    expect(screen.getAllByTestId('widget-popover')).toHaveLength(2);
    expect(screen.getByTestId('widget-variables-marker')).toBeInTheDocument();
  });

  it('shows no marker when none is asked for', () => {
    testRender(<Host isEditable names={undefined} />);
    expect(screen.queryByTestId('widget-variables-marker')).not.toBeInTheDocument();
    expect(screen.getAllByTestId('widget-popover')).toHaveLength(2);
  });
});
