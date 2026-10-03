import { screen } from '@testing-library/react';
import React, { lazy } from 'react';
import { Route, Routes } from 'react-router';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import Root from './Root';
import type { CurationTab } from './curationTabs';

const tab = (path: string, label: string): CurationTab => ({
  path,
  label,
  component: lazy(async () => ({ default: () => <div>{`${path} content`}</div> })),
});

const TABS = [tab('inbox', 'Inbox'), tab('conflicts', 'Conflicts'), tab('stale', 'Stale knowledge')];

const renderCuration = (tabs: CurationTab[], route: string) => testRender(
  <Routes>
    <Route path="/dashboard/data/curation/*" element={<Root tabs={tabs} />} />
    <Route path="/dashboard/data" element={<div>data page</div>} />
  </Routes>,
  { route },
);

describe('Curation hub', () => {
  it('opens the first tab from the hub path', async () => {
    renderCuration(TABS, '/dashboard/data/curation');
    expect(await screen.findByText('inbox content')).toBeInTheDocument();
    expect(window.location.pathname).toEqual('/dashboard/data/curation/inbox');
  });

  it('lists every registered tab as a link, in registration order', async () => {
    renderCuration(TABS, '/dashboard/data/curation/conflicts');
    expect(await screen.findByText('conflicts content')).toBeInTheDocument();
    const links = ['inbox', 'conflicts', 'stale'].map((path) => screen.getByTestId(`curation-tab-${path}`));
    expect(links.map((link) => link.getAttribute('href'))).toEqual([
      '/dashboard/data/curation/inbox',
      '/dashboard/data/curation/conflicts',
      '/dashboard/data/curation/stale',
    ]);
    expect(links.map((link) => link.textContent)).toEqual(['Inbox', 'Conflicts', 'Stale knowledge']);
  });

  it('names the current tab in the breadcrumbs', async () => {
    renderCuration(TABS, '/dashboard/data/curation/stale');
    expect(await screen.findByText('stale content')).toBeInTheDocument();
    expect(screen.getAllByText('Stale knowledge').length).toBeGreaterThanOrEqual(2);
  });

  it('sends an unknown tab back to the first one', async () => {
    renderCuration(TABS, '/dashboard/data/curation/unknown');
    expect(await screen.findByText('inbox content')).toBeInTheDocument();
  });

  it('sends the reader back to Data while no tab is registered', async () => {
    renderCuration([], '/dashboard/data/curation');
    expect(await screen.findByText('data page')).toBeInTheDocument();
  });
});
