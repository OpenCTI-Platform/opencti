import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router';
import testRender from '../../../utils/tests/test-render';
import Root from './Root';

let capabilities: string[] = [];
let draftContext: { id: string } | null = null;
vi.mock('../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useAuth')>()),
  default: () => ({ me: { capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [], draftContext } }),
}));
vi.mock('../../../utils/hooks/useHelper', () => ({ default: () => ({ isFeatureEnable: () => true, isTrashEnable: () => true }) }));
vi.mock('../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../../../utils/hooks/useEntitySettings', () => ({ useHiddenEntities: () => [] }));

// The pages are heavy: stub them, the routing is what is tested.
vi.mock('./Drafts', () => ({ default: () => <div>Drafts listing</div> }));
vi.mock('./DraftRoot', () => ({ default: () => <div>Draft overview</div> }));

// Mounted like Index.tsx does: straight on `/data/import/draft/*`, not through data/Root.tsx.
const open = (route: string) => testRender(
  <Routes>
    <Route path="/dashboard/data/import/draft/*" element={<Root />} />
    <Route path="/dashboard" element={<div>Home</div>} />
  </Routes>,
  { route },
);

describe('Drafts Root routing', () => {
  beforeEach(() => {
    capabilities = [];
    draftContext = null;
  });

  it('redirects a user without the Drafts capabilities away from the listing', async () => {
    capabilities = ['KNOWLEDGE'];
    open('/dashboard/data/import/draft');
    await waitFor(() => expect(window.location.pathname).toBe('/dashboard'));
    expect(screen.queryByText('Drafts listing')).toBeNull();
  });

  it.each(['KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNASKIMPORT'])('opens the listing to a user with %s', async (capability) => {
    capabilities = [capability];
    open('/dashboard/data/import/draft');
    expect(await screen.findByText('Drafts listing')).toBeInTheDocument();
  });

  it('sends a user working in a draft to its overview, although the listing is not available in a draft', async () => {
    capabilities = ['KNOWLEDGE_KNUPDATE'];
    draftContext = { id: 'draft-id' };
    open('/dashboard/data/import/draft');
    expect(await screen.findByText('Draft overview')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/dashboard/data/import/draft/draft-id/');
  });

  it('keeps the overview of a draft open, it has no entry to follow', async () => {
    capabilities = [];
    open('/dashboard/data/import/draft/draft-id');
    expect(await screen.findByText('Draft overview')).toBeInTheDocument();
  });
});
