import { screen, within } from '@testing-library/react';
import React, { type ComponentType, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import Root from './Root';
import type { CurationTab } from './curationTabs';

const tab = (path: string, label: string): CurationTab => ({
  order: 0,
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
  afterEach(() => {
    vi.restoreAllMocks();
  });

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

  it('keeps the breadcrumb and the tab bar on screen while the code of a tab loads', async () => {
    const loading = lazy(() => new Promise<{ default: ComponentType }>(() => {}));
    renderCuration([{ ...tab('inbox', 'Inbox'), component: loading }, tab('conflicts', 'Conflicts')], '/dashboard/data/curation/inbox');
    expect(await screen.findByTestId('curation-tab-conflicts')).toBeInTheDocument();
    expect(screen.getByText('Curation')).toBeInTheDocument();
  });

  it('shows the pending count of a tab next to its label, and nothing for a tab with none', async () => {
    const inbox: CurationTab = { ...tab('inbox', 'Inbox'), useBadgeCount: () => 4 };
    const conflicts: CurationTab = { ...tab('conflicts', 'Conflicts'), useBadgeCount: () => 0 };
    renderCuration([inbox, conflicts], '/dashboard/data/curation/inbox');
    expect(await screen.findByText('inbox content')).toBeInTheDocument();
    const inboxTab = screen.getByTestId('curation-tab-inbox');
    expect(within(inboxTab).getByText('4')).toBeInTheDocument();
    expect(within(inboxTab).getByText('4 pending')).toBeInTheDocument();
    expect(screen.getByTestId('curation-tab-conflicts').textContent).toEqual('Conflicts');
  });

  it('hides the count of a tab whose count cannot be read, and keeps the tab', async () => {
    const inbox: CurationTab = {
      ...tab('inbox', 'Inbox'),
      useBadgeCount: () => {
        throw new Error('count unavailable');
      },
    };
    vi.spyOn(console, 'error').mockImplementation(() => {});
    renderCuration([inbox], '/dashboard/data/curation/inbox');
    expect(await screen.findByText('inbox content')).toBeInTheDocument();
    expect(screen.getByTestId('curation-tab-inbox').textContent).toEqual('Inbox');
  });

  it('tells a reader with no tab that nothing in Curation is available, with a way back to Data', async () => {
    renderCuration([], '/dashboard/data/curation');
    expect(await screen.findByText('Nothing in Curation is available to you')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to Data' })).toHaveAttribute('href', '/dashboard/data');
    expect(screen.queryByText('data page')).not.toBeInTheDocument();
  });
});
