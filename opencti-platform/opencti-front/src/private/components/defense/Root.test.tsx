import { screen } from '@testing-library/react';
import React, { lazy } from 'react';
import { Route, Routes } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../utils/tests/test-render';
import Root from './Root';
import type { DefenseArea } from './defenseAreas';

const hidden = vi.hoisted(() => ({ entities: [] as string[] }));
vi.mock('../../../utils/hooks/useEntitySettings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useEntitySettings')>()),
  useHiddenEntities: () => hidden.entities,
}));

const area = (path: string, entityType?: string): DefenseArea => ({
  path,
  label: path,
  icon: null,
  entityType,
  component: lazy(async () => ({ default: () => <div>{`${path} area`}</div> })),
});

const AREAS = [area('hunts', 'Hunt'), area('matrix'), area('assurance')];

const renderDefense = (areas: DefenseArea[], route: string) => testRender(
  <Routes>
    <Route path="/dashboard/defense/*" element={<Root areas={areas} />} />
    <Route path="/dashboard" element={<div>home page</div>} />
  </Routes>,
  { route },
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
    renderDefense(AREAS, '/dashboard/defense/assurance/lists');
    expect(await screen.findByText('assurance area')).toBeInTheDocument();
  });

  it('skips an area whose entity type is hidden, for the landing page and the route', async () => {
    hidden.entities = ['Hunt'];
    renderDefense(AREAS, '/dashboard/defense/hunts');
    expect(await screen.findByText('matrix area')).toBeInTheDocument();
    expect(screen.queryByText('hunts area')).not.toBeInTheDocument();
  });

  it('sends an unknown path back to the first area', async () => {
    renderDefense(AREAS, '/dashboard/defense/unknown');
    expect(await screen.findByText('hunts area')).toBeInTheDocument();
  });

  it('falls back to the home page while no area is registered', async () => {
    renderDefense([], '/dashboard/defense');
    expect(await screen.findByText('home page')).toBeInTheDocument();
  });
});
