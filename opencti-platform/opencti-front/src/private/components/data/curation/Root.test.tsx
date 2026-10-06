import { screen, within } from '@testing-library/react';
import React, { type ComponentType, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import Root from './Root';
import { CURATION_DOCUMENTATION_URL, type CurationTab } from './curationTabs';

const tab = (path: string, label: string): CurationTab => ({
  order: 0,
  path,
  label,
  component: lazy(async () => ({ default: () => <div>{`${path} content`}</div> })),
});

const TABS = [tab('alpha', 'Alpha'), tab('beta', 'Beta'), tab('gamma', 'Gamma page')];

const KNOWLEDGE_READER = [{ name: 'KNOWLEDGE' }];

const renderCuration = (tabs: CurationTab[], route: string, capabilities = KNOWLEDGE_READER) => testRender(
  <Routes>
    <Route path="/dashboard/data/curation/*" element={<Root tabs={tabs} />} />
    <Route path="/dashboard/data" element={<div>data page</div>} />
  </Routes>,
  { route, userContext: createMockUserContext({ me: { capabilities } }) },
);

describe('Curation hub', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('opens the first tab from the hub path', async () => {
    renderCuration(TABS, '/dashboard/data/curation');
    expect(await screen.findByText('alpha content')).toBeInTheDocument();
    expect(window.location.pathname).toEqual('/dashboard/data/curation/alpha');
  });

  it('lists every registered tab as a link, in registration order', async () => {
    renderCuration(TABS, '/dashboard/data/curation/beta');
    expect(await screen.findByText('beta content')).toBeInTheDocument();
    const links = ['alpha', 'beta', 'gamma'].map((path) => screen.getByTestId(`curation-tab-${path}`));
    expect(links.map((link) => link.getAttribute('href'))).toEqual([
      '/dashboard/data/curation/alpha',
      '/dashboard/data/curation/beta',
      '/dashboard/data/curation/gamma',
    ]);
    expect(links.map((link) => link.textContent)).toEqual(['Alpha', 'Beta', 'Gamma page']);
  });

  it('names the current tab in the breadcrumbs', async () => {
    renderCuration(TABS, '/dashboard/data/curation/gamma');
    expect(await screen.findByText('gamma content')).toBeInTheDocument();
    expect(screen.getAllByText('Gamma page').length).toBeGreaterThanOrEqual(2);
  });

  it('sends an unknown tab back to the first one', async () => {
    renderCuration(TABS, '/dashboard/data/curation/unknown');
    expect(await screen.findByText('alpha content')).toBeInTheDocument();
  });

  it('keeps the breadcrumb and the tab bar on screen while the code of a tab loads', async () => {
    const loading = lazy(() => new Promise<{ default: ComponentType }>(() => {}));
    renderCuration([{ ...tab('alpha', 'Alpha'), component: loading }, tab('beta', 'Beta')], '/dashboard/data/curation/alpha');
    expect(await screen.findByTestId('curation-tab-beta')).toBeInTheDocument();
    expect(screen.getByText('Curation')).toBeInTheDocument();
  });

  it('shows the pending count of a tab next to its label, and nothing for a tab with none', async () => {
    const alpha: CurationTab = { ...tab('alpha', 'Alpha'), useBadgeCount: () => 4 };
    const beta: CurationTab = { ...tab('beta', 'Beta'), useBadgeCount: () => 0 };
    renderCuration([alpha, beta], '/dashboard/data/curation/alpha');
    expect(await screen.findByText('alpha content')).toBeInTheDocument();
    const alphaTab = screen.getByTestId('curation-tab-alpha');
    expect(within(alphaTab).getByText('4')).toBeInTheDocument();
    expect(within(alphaTab).getByText('4 pending')).toBeInTheDocument();
    expect(screen.getByTestId('curation-tab-beta').textContent).toEqual('Beta');
  });

  it('hides the count of a tab whose count cannot be read, and keeps the tab', async () => {
    const alpha: CurationTab = {
      ...tab('alpha', 'Alpha'),
      useBadgeCount: () => {
        throw new Error('count unavailable');
      },
    };
    vi.spyOn(console, 'error').mockImplementation(() => {});
    renderCuration([alpha], '/dashboard/data/curation/alpha');
    expect(await screen.findByText('alpha content')).toBeInTheDocument();
    expect(screen.getByTestId('curation-tab-alpha').textContent).toEqual('Alpha');
  });

  it('lands on the first-use page of the hub while no tab is registered', async () => {
    renderCuration([], '/dashboard/data/curation');
    expect(await screen.findByTestId('hub-first-use')).toBeInTheDocument();
    expect(screen.getByText('Data')).toBeInTheDocument();
    expect(screen.getAllByText('Curation').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Keep your knowledge base clean and trustworthy, from one place.')).toBeInTheDocument();
    expect(screen.getByTestId('hub-empty')).toHaveTextContent('No Curation page is available on this platform yet.');
    expect(screen.getByRole('link', { name: 'Read the documentation' })).toHaveAttribute('href', CURATION_DOCUMENTATION_URL);
  });

  it('sends any path below an empty hub to its landing page', async () => {
    renderCuration([], '/dashboard/data/curation/alpha');
    expect(await screen.findByTestId('hub-empty')).toBeInTheDocument();
    expect(window.location.pathname).toEqual('/dashboard/data/curation');
  });

  it('tells a reader with no granted tab that nothing in Curation is available, with a way back to Data', async () => {
    renderCuration([{ ...tab('alpha', 'Alpha'), needs: ['KNOWLEDGE_KNUPDATE_KNMERGE'] }], '/dashboard/data/curation');
    expect(await screen.findByText('Nothing in Curation is available to you')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to Data' })).toHaveAttribute('href', '/dashboard/data');
    expect(screen.queryByText('data page')).not.toBeInTheDocument();
  });

  it('hides a tab whose platform module is disabled', async () => {
    const alpha: CurationTab = { ...tab('alpha', 'Alpha'), isAvailable: () => false };
    renderCuration([alpha, tab('beta', 'Beta')], '/dashboard/data/curation');
    expect(await screen.findByText('beta content')).toBeInTheDocument();
    expect(screen.queryByTestId('curation-tab-alpha')).not.toBeInTheDocument();
  });

  it('applies the knowledge access of the menu to a direct link, empty hub included', async () => {
    renderCuration(TABS, '/dashboard/data/curation/alpha', []);
    expect(await screen.findByText('Nothing in Curation is available to you')).toBeInTheDocument();
    expect(screen.queryByText('alpha content')).not.toBeInTheDocument();
  });

  it('shows the landing page of an empty hub to the readers of the knowledge only', async () => {
    renderCuration([], '/dashboard/data/curation', []);
    expect(await screen.findByText('Nothing in Curation is available to you')).toBeInTheDocument();
    expect(screen.queryByTestId('hub-empty')).not.toBeInTheDocument();
  });
});
