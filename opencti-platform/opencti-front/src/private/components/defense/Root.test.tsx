import { screen } from '@testing-library/react';
import React, { type ComponentType, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import HubFirstUse from '../common/hub/HubFirstUse';
import Root from './Root';
import { type DefenseArea, DEFENSE_DOCUMENTATION_URL } from './defenseAreas';

const hidden = vi.hoisted(() => ({ entities: [] as string[] }));
vi.mock('../../../utils/hooks/useEntitySettings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useEntitySettings')>()),
  useHiddenEntities: () => hidden.entities,
}));

const area = (path: string, entityType?: string): DefenseArea => ({
  order: 0,
  path,
  label: path,
  icon: null,
  entityType,
  component: lazy(async () => ({ default: () => <div>{`${path} area`}</div> })),
});

// An area whose code never finishes loading.
const loading = lazy(() => new Promise<{ default: ComponentType }>(() => {}));

const AREAS = [area('alpha', 'Report'), area('beta'), area('gamma')];

const KNOWLEDGE_READER = [{ name: 'KNOWLEDGE' }];

const renderDefense = (areas: DefenseArea[], route: string, capabilities = KNOWLEDGE_READER) => testRender(
  <Routes>
    <Route path="/dashboard/defense/*" element={<Root areas={areas} />} />
    <Route path="/dashboard" element={<div>home page</div>} />
  </Routes>,
  { route, userContext: createMockUserContext({ me: { capabilities } }) },
);

describe('Defense root', () => {
  beforeEach(() => {
    hidden.entities = [];
  });

  it('opens the first area from the hub path', async () => {
    renderDefense(AREAS, '/dashboard/defense');
    expect(await screen.findByText('alpha area')).toBeInTheDocument();
    expect(window.location.pathname).toEqual('/dashboard/defense/alpha');
  });

  it('mounts every area under its own path, deep links included', async () => {
    renderDefense(AREAS, '/dashboard/defense/gamma/lists');
    expect(await screen.findByText('gamma area')).toBeInTheDocument();
  });

  it('skips an area whose entity type is hidden, for the landing page and the route', async () => {
    hidden.entities = ['Report'];
    renderDefense(AREAS, '/dashboard/defense/alpha');
    expect(await screen.findByText('beta area')).toBeInTheDocument();
    expect(screen.queryByText('alpha area')).not.toBeInTheDocument();
  });

  it('sends an unknown path back to the first area', async () => {
    renderDefense(AREAS, '/dashboard/defense/unknown');
    expect(await screen.findByText('alpha area')).toBeInTheDocument();
  });

  it('owns the breadcrumb of every area, Defense then the area', async () => {
    renderDefense([{ ...area('beta'), label: 'Beta area page' }], '/dashboard/defense/beta');
    expect(await screen.findByText('beta area')).toBeInTheDocument();
    expect(screen.getByText('Defense')).toBeInTheDocument();
    expect(screen.getByText('Beta area page')).toBeInTheDocument();
  });

  it('keeps the breadcrumb on screen while the code of an area loads', async () => {
    renderDefense([{ ...area('alpha'), label: 'Alpha', component: loading }], '/dashboard/defense/alpha');
    expect(await screen.findByText('Alpha')).toBeInTheDocument();
    expect(screen.getByText('Defense')).toBeInTheDocument();
  });

  it('names the open section in the breadcrumb and lists the sections as tabs', async () => {
    const gamma: DefenseArea = {
      ...area('gamma'),
      label: 'Gamma',
      sections: [{ path: 'overview', label: 'Overview' }, { path: 'lists', label: 'Lists' }],
    };
    renderDefense([gamma], '/dashboard/defense/gamma/lists');
    expect(await screen.findByText('gamma area')).toBeInTheDocument();
    const tabs = ['overview', 'lists'].map((path) => screen.getByTestId(`defense-gamma-section-${path}`));
    expect(tabs.map((tab) => tab.getAttribute('href'))).toEqual([
      '/dashboard/defense/gamma/overview',
      '/dashboard/defense/gamma/lists',
    ]);
    expect(screen.getAllByText('Lists').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole('link', { name: 'Gamma' })).toHaveAttribute('href', '/dashboard/defense/gamma');
  });

  it('adds no container or breadcrumb around a page the area renders itself', async () => {
    const alpha: DefenseArea = { ...area('alpha'), label: 'Alpha', rendersOwnPage: (subPath) => subPath.length > 0 };
    renderDefense([alpha], '/dashboard/defense/alpha/object-1/overview');
    expect(await screen.findByText('alpha area')).toBeInTheDocument();
    expect(screen.queryByText('Defense')).not.toBeInTheDocument();
  });

  it('gives an area its first-use state from its registry entry', async () => {
    const alpha: DefenseArea = {
      ...area('alpha'),
      label: 'Alpha',
      description: 'What does this area answer?',
      component: lazy(async () => ({ default: () => <HubFirstUse documentationUrl={DEFENSE_DOCUMENTATION_URL} /> })),
    };
    renderDefense([alpha], '/dashboard/defense/alpha');
    expect(await screen.findByTestId('hub-first-use')).toBeInTheDocument();
    expect(screen.getByText('What does this area answer?')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Read the documentation' })).toHaveAttribute('href', DEFENSE_DOCUMENTATION_URL);
  });

  it('lands on the first-use page of the hub while no area is registered', async () => {
    renderDefense([], '/dashboard/defense');
    expect(await screen.findByTestId('hub-first-use')).toBeInTheDocument();
    expect(screen.getAllByText('Defense').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Turn your threat knowledge into detection and proof.')).toBeInTheDocument();
    expect(screen.getByTestId('hub-empty')).toHaveTextContent('No Defense area is available on this platform yet.');
    expect(screen.getByRole('link', { name: 'Read the documentation' })).toHaveAttribute('href', DEFENSE_DOCUMENTATION_URL);
    expect(screen.queryByTestId('hub-no-access')).not.toBeInTheDocument();
    expect(screen.getByTestId('hub-breadcrumb-separator')).toHaveAttribute('aria-hidden', 'true');
  });

  it('sends any path below an empty hub to its landing page', async () => {
    renderDefense([], '/dashboard/defense/alpha/object-1');
    expect(await screen.findByTestId('hub-empty')).toBeInTheDocument();
    expect(window.location.pathname).toEqual('/dashboard/defense');
  });

  it('tells a reader whose areas are all hidden that nothing in Defense is available, with a way back', async () => {
    hidden.entities = ['Report'];
    renderDefense([area('alpha', 'Report')], '/dashboard/defense');
    expect(await screen.findByText('Nothing in Defense is available to you')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the dashboard' })).toHaveAttribute('href', '/dashboard');
    expect(screen.getByTestId('hub-breadcrumb-separator')).toHaveAttribute('aria-hidden', 'true');
    expect(screen.queryByTestId('hub-empty')).not.toBeInTheDocument();
    expect(screen.queryByText('home page')).not.toBeInTheDocument();
  });

  it('applies the knowledge access of the menu to a direct link, before the needs of each area', async () => {
    renderDefense(AREAS, '/dashboard/defense/beta', []);
    expect(await screen.findByText('Nothing in Defense is available to you')).toBeInTheDocument();
    expect(screen.queryByText('beta area')).not.toBeInTheDocument();
  });

  it('shows the landing page of an empty hub to the readers of the knowledge only', async () => {
    renderDefense([], '/dashboard/defense', []);
    expect(await screen.findByText('Nothing in Defense is available to you')).toBeInTheDocument();
    expect(screen.queryByTestId('hub-empty')).not.toBeInTheDocument();
  });
});
