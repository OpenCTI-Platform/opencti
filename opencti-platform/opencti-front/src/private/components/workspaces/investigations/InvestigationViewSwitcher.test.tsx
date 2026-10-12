import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import InvestigationViewSwitcher, { INVESTIGATION_MATRIX_EXPORT_ID, useInvestigationView } from './InvestigationViewSwitcher';

const ViewProbe = () => {
  const view = useInvestigationView();
  return <span data-testid="current-view">{view}</span>;
};

const renderAt = (route: string) => testRender(
  <>
    <ViewProbe />
    <InvestigationViewSwitcher investigationId="abc" />
  </>,
  { route },
);

describe('InvestigationViewSwitcher', () => {
  it('selects the graph view on the investigation root path', () => {
    renderAt('/dashboard/workspaces/investigations/abc');

    expect(screen.getByTestId('current-view')).toHaveTextContent('graph');
    const graphLink = screen.getByRole('radio', { name: 'Graph view' });
    const matrixLink = screen.getByRole('radio', { name: 'Tactics matrix view' });
    expect(graphLink).toHaveAttribute('href', '/dashboard/workspaces/investigations/abc');
    expect(matrixLink.getAttribute('href')).toMatch(/\/dashboard\/workspaces\/investigations\/abc\/matrix$/);
    expect(graphLink).toHaveAttribute('aria-checked', 'true');
    expect(matrixLink).toHaveAttribute('aria-checked', 'false');
  });

  it('selects the matrix view on the matrix path', () => {
    renderAt('/dashboard/workspaces/investigations/abc/matrix');

    expect(screen.getByTestId('current-view')).toHaveTextContent('matrix');
    expect(screen.getByRole('radio', { name: 'Tactics matrix view' })).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('radio', { name: 'Graph view' })).toHaveAttribute('aria-checked', 'false');
  });

  it('exports a stable DOM id for the matrix export target', () => {
    expect(INVESTIGATION_MATRIX_EXPORT_ID).toBe('investigation-matrix-export');
  });
});
