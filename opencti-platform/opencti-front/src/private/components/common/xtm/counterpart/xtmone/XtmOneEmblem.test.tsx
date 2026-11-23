import React from 'react';
import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import { XtmEmblem, XtmEmblems, EMBLEM_FOUND, EMBLEM_MUTED, emblemInk } from '../core/XtmEmblem';
import { OPENAEV_PRODUCT, XTMONE_PRODUCT, xtmProductsFor } from '../core/xtmProducts';
import { previewFactsOf, XTMONE_FACTS } from '../core/counterpartFacts';
import { resetXtmCounterpartCache } from '../core/useXtmCounterparts';

type Result = { id: string; product: string; status: string; counterpart: Record<string, unknown> | null };

const mocks = vi.hoisted(() => ({
  connected: true,
  results: [] as Result[],
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      if (!('ids' in variables)) {
        return Promise.resolve({ xtmConnections: ['xtmone', 'openaev', 'opencrq'].map((product) => ({ product, connected: mocks.connected })) });
      }
      const ids = variables.ids as string[];
      return Promise.resolve({ xtmCounterpartsOf: mocks.results.filter((r) => ids.includes(r.id)).map((r) => ({ ...r, source_id: r.id })) });
    },
  }),
}));

vi.mock('../../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../utils/hooks/useGranted')>()),
  default: () => true,
}));

const asset = {
  key: 'web-01',
  product: 'xtmone',
  object_id: 'asset-1',
  object_type: 'asset',
  object_name: 'web-01',
  object_url: 'https://one.example/ctem/inventory/assets/asset-1',
  facts: [{ key: 'criticality', value: 'high' }],
};

describe('XTM One emblem (Contract v3: leftmost, XTM One purple when found)', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.results = [];
  });

  it('draws XTM One first on a system, then OpenAEV, then OpenCRQ', () => {
    expect(xtmProductsFor('System').map((p) => p.product)).toEqual(['xtmone', 'openaev', 'opencrq']);
    expect(xtmProductsFor('Vulnerability').map((p) => p.product)).not.toContain('xtmone');
  });

  it('found: a link to the XTM One inventory, its mark in the canonical XTM One purple', async () => {
    mocks.results = [{ id: 'sys-1', product: 'xtmone', status: 'found', counterpart: asset }];
    testRender(<XtmEmblem product={XTMONE_PRODUCT} objectId="sys-1" />);
    const link = await screen.findByRole('link', { name: 'Open in XTM One' });
    expect(link).toHaveAttribute('href', asset.object_url);
    expect(link).toHaveAttribute('data-status', 'match');
    expect(emblemInk(XTMONE_PRODUCT, true)).toBe('var(--color-filigran-ia-primary)');
    // Only XTM One is purple: the other products keep the theme highlight.
    expect(emblemInk(OPENAEV_PRODUCT, true)).toBe(EMBLEM_FOUND);
  });

  it('not found and not connected: greyed like the other emblems, never purple', async () => {
    mocks.results = [{ id: 'sys-1', product: 'xtmone', status: 'not_found', counterpart: null }];
    testRender(<XtmEmblem product={XTMONE_PRODUCT} objectId="sys-1" />);
    const emblem = await screen.findByRole('button', { name: 'Not found in XTM One' });
    expect(emblem).toHaveAttribute('aria-disabled', 'true');
    expect(emblemInk(XTMONE_PRODUCT, false)).toBe(EMBLEM_MUTED);
  });

  it('renders the emblems in order in the header', async () => {
    // Not connected: every emblem is drawn (greyed), so the order is visible.
    mocks.connected = false;
    testRender(<XtmEmblems products={xtmProductsFor('System')} objectId="sys-1" />);
    const first = await screen.findByTestId('xtmone-emblem');
    const aev = await screen.findByTestId('openaev-emblem');
    expect(first.compareDocumentPosition(aev) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('shows the inventory criticality and category as words', () => {
    const format = { t_i18n: (s: string) => s, count: String, money: String, date: String };
    expect(previewFactsOf([{ key: 'category', value: 'server' }, { key: 'criticality', value: 'high' }, { key: 'owner', value: 'x' }], XTMONE_FACTS, format))
      .toEqual([{ label: 'Criticality', value: 'high' }, { label: 'Category', value: 'server' }]);
  });
});
