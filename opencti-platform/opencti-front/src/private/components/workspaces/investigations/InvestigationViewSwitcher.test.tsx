import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { useLocation } from 'react-router';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import InvestigationViewSwitcher, { INVESTIGATION_MATRIX_EXPORT_ID, useInvestigationView } from './InvestigationViewSwitcher';

const ViewProbe = () => {
  const view = useInvestigationView();
  return <span data-testid="current-view">{view}</span>;
};

const LocationProbe = () => <span data-testid="current-path">{useLocation().pathname}</span>;

const KNOWLEDGE_USER = [{ name: 'KNOWLEDGE' }];
const INVESTIGATION_ONLY_USER = [{ name: 'INVESTIGATION' }];

const renderAt = (route: string, capabilities = KNOWLEDGE_USER) => testRender(
  <>
    <ViewProbe />
    <LocationProbe />
    <InvestigationViewSwitcher investigationId="abc" />
  </>,
  { route, userContext: createMockUserContext({ me: { name: 'analyst', capabilities } }) },
);

describe('InvestigationViewSwitcher', () => {
  it('selects the graph view on the investigation root path', () => {
    renderAt('/dashboard/workspaces/investigations/abc');

    expect(screen.getByTestId('current-view')).toHaveTextContent('graph');
    const graphLink = screen.getByRole('radio', { name: 'Graph view' });
    const matrixLink = screen.getByRole('radio', { name: 'Matrix view' });
    expect(graphLink).toHaveAttribute('href', '/dashboard/workspaces/investigations/abc');
    expect(matrixLink.getAttribute('href')).toMatch(/\/dashboard\/workspaces\/investigations\/abc\/matrix$/);
    expect(graphLink).toHaveAttribute('aria-checked', 'true');
    expect(matrixLink).toHaveAttribute('aria-checked', 'false');
  });

  it('selects the matrix view on the matrix path', () => {
    renderAt('/dashboard/workspaces/investigations/abc/matrix');

    expect(screen.getByTestId('current-view')).toHaveTextContent('matrix');
    expect(screen.getByRole('radio', { name: 'Matrix view' })).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('radio', { name: 'Graph view' })).toHaveAttribute('aria-checked', 'false');
  });

  it('hides the switch from a user without KNOWLEDGE', () => {
    renderAt('/dashboard/workspaces/investigations/abc', INVESTIGATION_ONLY_USER);

    expect(screen.getByTestId('current-view')).toHaveTextContent('graph');
    expect(screen.queryAllByRole('radio')).toHaveLength(0);
  });

  it('sends a user without KNOWLEDGE from the matrix path back to the graph', () => {
    renderAt('/dashboard/workspaces/investigations/abc/matrix', INVESTIGATION_ONLY_USER);

    expect(screen.getByTestId('current-view')).toHaveTextContent('graph');
    expect(screen.getByTestId('current-path')).toHaveTextContent(/^\/dashboard\/workspaces\/investigations\/abc$/);
  });

  it('exports a stable DOM id for the matrix export target', () => {
    expect(INVESTIGATION_MATRIX_EXPORT_ID).toBe('investigation-matrix-export');
  });
});
