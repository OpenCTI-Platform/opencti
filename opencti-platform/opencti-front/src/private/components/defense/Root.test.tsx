import { screen } from '@testing-library/react';
import React, { type ComponentType, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import Root from './Root';
import type { DefenseArea } from './defenseAreas';

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

const AREAS = [area('hunts', 'Hunt'), area('second'), area('third')];

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
    expect(await screen.findByText('hunts area')).toBeInTheDocument();
    expect(window.location.pathname).toEqual('/dashboard/defense/hunts');
  });

  it('mounts every area under its own path, deep links included', async () => {
    renderDefense(AREAS, '/dashboard/defense/third/lists');
    expect(await screen.findByText('third area')).toBeInTheDocument();
  });

  it('skips an area whose entity type is hidden, for the landing page and the route', async () => {
    hidden.entities = ['Hunt'];
    renderDefense(AREAS, '/dashboard/defense/hunts');
    expect(await screen.findByText('second area')).toBeInTheDocument();
    expect(screen.queryByText('hunts area')).not.toBeInTheDocument();
  });

  it('sends an unknown path back to the first area', async () => {
    renderDefense(AREAS, '/dashboard/defense/unknown');
    expect(await screen.findByText('hunts area')).toBeInTheDocument();
  });

  it('owns the breadcrumb of every area, Defense then the area', async () => {
    renderDefense([{ ...area('hunts'), label: 'Hunts' }], '/dashboard/defense/hunts');
    expect(await screen.findByText('hunts area')).toBeInTheDocument();
    expect(screen.getByText('Defense')).toBeInTheDocument();
    expect(screen.getByText('Hunts')).toBeInTheDocument();
  });

  it('keeps the breadcrumb on screen while the code of an area loads', async () => {
    renderDefense([{ ...area('hunts'), label: 'Hunts', component: loading }], '/dashboard/defense/hunts');
    expect(await screen.findByText('Hunts')).toBeInTheDocument();
    expect(screen.getByText('Defense')).toBeInTheDocument();
  });

  it('adds no container or breadcrumb around a page the area renders itself', async () => {
    const hunts: DefenseArea = { ...area('hunts'), label: 'Hunts', rendersOwnPage: (subPath) => subPath.length > 0 };
    renderDefense([hunts], '/dashboard/defense/hunts/hunt-1/overview');
    expect(await screen.findByText('hunts area')).toBeInTheDocument();
    expect(screen.queryByText('Defense')).not.toBeInTheDocument();
  });

  it('tells a reader with no area that nothing in Defense is available, with a way back', async () => {
    renderDefense([], '/dashboard/defense');
    expect(await screen.findByText('Nothing in Defense is available to you')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the dashboard' })).toHaveAttribute('href', '/dashboard');
    expect(screen.queryByText('home page')).not.toBeInTheDocument();
    // The one-entry breadcrumb keeps the height of a row with a separator, so the alert starts where core pages start
    expect(screen.getByTestId('hub-breadcrumb-separator')).toHaveAttribute('aria-hidden', 'true');
  });

  it('applies the knowledge access of the menu to a direct link, before the needs of each area', async () => {
    renderDefense(AREAS, '/dashboard/defense/second', []);
    expect(await screen.findByText('Nothing in Defense is available to you')).toBeInTheDocument();
    expect(screen.queryByText('second area')).not.toBeInTheDocument();
  });
});
