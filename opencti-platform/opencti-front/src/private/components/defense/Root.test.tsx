import { screen } from '@testing-library/react';
import React, { type ComponentType, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { describe, expect, it } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import HubFirstUse from '../common/hub/HubFirstUse';
import Root from './Root';
import type { DefenseArea } from './defenseAreas';

const area = (path: string, needs?: string[]): DefenseArea => ({
  order: 0,
  path,
  label: path,
  icon: null,
  needs,
  component: lazy(async () => ({ default: () => <div>{`${path} area`}</div> })),
});

// An area whose code never finishes loading.
const loading = lazy(() => new Promise<{ default: ComponentType }>(() => {}));

const AREAS = [area('assurance'), area('second')];

const KNOWLEDGE_READER = [{ name: 'KNOWLEDGE' }];

const renderDefense = (areas: DefenseArea[], route: string, capabilities = KNOWLEDGE_READER) => testRender(
  <Routes>
    <Route path="/dashboard/defense/*" element={<Root areas={areas} />} />
    <Route path="/dashboard" element={<div>home page</div>} />
  </Routes>,
  { route, userContext: createMockUserContext({ me: { capabilities } }) },
);

describe('Defense root', () => {
  it('opens the first area from the hub path', async () => {
    renderDefense(AREAS, '/dashboard/defense');
    expect(await screen.findByText('assurance area')).toBeInTheDocument();
    expect(window.location.pathname).toEqual('/dashboard/defense/assurance');
  });

  it('mounts every area under its own path, deep links included', async () => {
    renderDefense(AREAS, '/dashboard/defense/second/details');
    expect(await screen.findByText('second area')).toBeInTheDocument();
  });

  it('skips an area the user is not granted, for the landing page and the route', async () => {
    renderDefense([area('restricted', ['KNOWLEDGE_KNUPDATE']), area('assurance')], '/dashboard/defense/restricted');
    expect(await screen.findByText('assurance area')).toBeInTheDocument();
    expect(screen.queryByText('restricted area')).not.toBeInTheDocument();
  });

  it('sends an unknown path back to the first area', async () => {
    renderDefense(AREAS, '/dashboard/defense/unknown');
    expect(await screen.findByText('assurance area')).toBeInTheDocument();
  });

  it('owns the breadcrumb of every area, Defense then the area', async () => {
    renderDefense([{ ...area('assurance'), label: 'Dissemination assurance' }], '/dashboard/defense/assurance');
    expect(await screen.findByText('assurance area')).toBeInTheDocument();
    expect(screen.getByText('Defense')).toBeInTheDocument();
    expect(screen.getByText('Dissemination assurance')).toBeInTheDocument();
  });

  it('keeps the breadcrumb on screen while the code of an area loads', async () => {
    renderDefense([{ ...area('assurance'), label: 'Dissemination assurance', component: loading }], '/dashboard/defense/assurance');
    expect(await screen.findByText('Dissemination assurance')).toBeInTheDocument();
    expect(screen.getByText('Defense')).toBeInTheDocument();
  });

  it('names the open section in the breadcrumb and lists the sections as tabs', async () => {
    const assurance: DefenseArea = {
      ...area('assurance'),
      label: 'Dissemination assurance',
      sections: [{ path: 'overview', label: 'Overview' }, { path: 'lists', label: 'Lists' }],
    };
    renderDefense([assurance], '/dashboard/defense/assurance/lists');
    expect(await screen.findByText('assurance area')).toBeInTheDocument();
    const tabs = ['overview', 'lists'].map((path) => screen.getByTestId(`defense-assurance-section-${path}`));
    expect(tabs.map((tab) => tab.getAttribute('href'))).toEqual([
      '/dashboard/defense/assurance/overview',
      '/dashboard/defense/assurance/lists',
    ]);
    expect(screen.getAllByText('Lists').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole('link', { name: 'Dissemination assurance' })).toHaveAttribute('href', '/dashboard/defense/assurance');
  });

  it('gives an area its first-use state from its registry entry', async () => {
    const assurance: DefenseArea = {
      ...area('assurance'),
      label: 'Dissemination assurance',
      description: 'Do the indicators you share reach your security platforms, and do they still work there?',
      component: lazy(async () => ({ default: () => <HubFirstUse documentationUrl="https://docs.opencti.io/latest/usage/dissemination-assurance/" /> })),
    };
    renderDefense([assurance], '/dashboard/defense/assurance');
    expect(await screen.findByTestId('hub-first-use')).toBeInTheDocument();
    expect(screen.getByText('Do the indicators you share reach your security platforms, and do they still work there?')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Read the documentation' })).toHaveAttribute(
      'href',
      'https://docs.opencti.io/latest/usage/dissemination-assurance/',
    );
  });

  it('tells a reader with no area that nothing in Defense is available, with a way back', async () => {
    renderDefense([], '/dashboard/defense');
    expect(await screen.findByText('Nothing in Defense is available to you')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the dashboard' })).toHaveAttribute('href', '/dashboard');
    expect(screen.queryByText('home page')).not.toBeInTheDocument();
  });

  it('applies the knowledge access of the menu to a direct link, before the needs of each area', async () => {
    renderDefense(AREAS, '/dashboard/defense/assurance', []);
    expect(await screen.findByText('Nothing in Defense is available to you')).toBeInTheDocument();
    expect(screen.queryByText('assurance area')).not.toBeInTheDocument();
  });
});
