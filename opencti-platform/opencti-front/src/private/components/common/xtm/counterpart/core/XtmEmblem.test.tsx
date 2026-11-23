import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import { XtmEmblem, XtmRowMark, safeCounterpartUrl } from './XtmEmblem';
import { OPENAEV_PRODUCT, xtmProductsFor } from './xtmProducts';
import { resetXtmCounterpartCache } from './useXtmCounterparts';
import { XTM_CONNECT_DOC_URL } from './xtmConnect';

type Result = { id: string; product: string; status: string; counterpart: Record<string, unknown> | null };

const mocks = vi.hoisted(() => ({
  flag: true,
  granted: true,
  connected: { xtmone: true, openaev: true, opencrq: true } as Record<string, boolean>,
  results: [] as Result[],
  calls: [] as Array<Record<string, unknown>>,
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      const isLookup = 'ids' in variables;
      mocks.calls.push({ isLookup, variables });
      if (!isLookup) {
        return Promise.resolve({ xtmConnections: Object.entries(mocks.connected).map(([product, connected]) => ({ product, connected })) });
      }
      const ids = variables.ids as string[];
      return Promise.resolve({ xtmCounterpartsOf: mocks.results.filter((r) => ids.includes(r.id)).map((r) => ({ ...r, source_id: r.id })) });
    },
  }),
}));

vi.mock('../../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../utils/hooks/useGranted')>()),
  default: () => mocks.granted,
}));

vi.mock('../../../../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (id: string) => id === 'XTM_COUNTERPARTS' && mocks.flag }),
}));

const aevCounterpart = {
  key: 'host-1',
  product: 'openaev',
  object_id: 'asset-1',
  object_type: 'Asset',
  object_name: 'host-1.example',
  object_url: 'https://aev.example/admin/assets/asset-1',
  facts: [],
};

const result = (id: string, product: string, status: string, counterpart: Record<string, unknown> | null = null): Result => ({ id, product, status, counterpart });

describe('XtmEmblem (single XTM emblem, Sam 23 Nov 2026)', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.flag = true;
    mocks.granted = true;
    mocks.connected = { xtmone: true, openaev: true, opencrq: true };
    mocks.results = [];
    mocks.calls = [];
  });

  it('draws nothing and sends nothing while the feature flag is off', async () => {
    mocks.flag = false;
    testRender(<XtmEmblem products={xtmProductsFor('System')} objectId="sys-1" />);
    await new Promise((resolve) => {
      setTimeout(resolve, 60);
    });
    expect(screen.queryByTestId('xtm-emblem')).not.toBeInTheDocument();
    expect(mocks.calls).toHaveLength(0);
  });

  it('one emblem only, active when one product holds the object, one batched lookup', async () => {
    mocks.results = [
      result('sys-1', 'openaev', 'found', aevCounterpart),
      result('sys-1', 'opencrq', 'not_found'),
      result('sys-1', 'xtmone', 'not_found'),
    ];
    testRender(<XtmEmblem products={xtmProductsFor('System')} objectId="sys-1" />);
    const emblem = await screen.findByRole('button', { name: 'Across the XTM Platform' });
    expect(screen.getAllByTestId('xtm-emblem')).toHaveLength(1);
    expect(emblem).toHaveAttribute('data-found', '1');
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(1);
  });

  it('greyed when no product holds the object', async () => {
    mocks.results = [result('sys-1', 'openaev', 'not_found'), result('sys-1', 'opencrq', 'not_found'), result('sys-1', 'xtmone', 'not_found')];
    testRender(<XtmEmblem products={xtmProductsFor('System')} objectId="sys-1" />);
    const emblem = await screen.findByRole('button', { name: 'Not found across the XTM Platform' });
    expect(emblem).toHaveAttribute('data-found', '0');
  });

  it('the click opens a surface with one section per product and a button to open the match', async () => {
    mocks.results = [result('sys-1', 'openaev', 'found', aevCounterpart), result('sys-1', 'opencrq', 'not_found')];
    mocks.connected = { xtmone: false, openaev: true, opencrq: true };
    const { user } = testRender(<XtmEmblem products={xtmProductsFor('System')} objectId="sys-1" />);
    await user.click(await screen.findByRole('button', { name: 'Across the XTM Platform' }));
    const surface = await screen.findByTestId('xtm-surface');
    expect(surface).toBeInTheDocument();
    expect(screen.getByTestId('openaev-section')).toHaveAttribute('data-status', 'found');
    expect(screen.getByTestId('opencrq-section')).toHaveAttribute('data-status', 'not_found');
    expect(screen.getByTestId('xtmone-section')).toHaveAttribute('data-status', 'not_connected');
    expect(screen.getByRole('link', { name: 'Open in OpenAEV' })).toHaveAttribute('href', aevCounterpart.object_url);
    expect(screen.getByRole('link', { name: 'Connect XTM One' })).toHaveAttribute('href', XTM_CONNECT_DOC_URL);
    // A design system separator between the three sections, none before the first.
    expect(screen.getAllByTestId('xtm-surface-separator')).toHaveLength(2);
  });

  it('a user who cannot configure the platform sees no "Connect" entry', async () => {
    mocks.granted = false;
    mocks.results = [result('sys-1', 'openaev', 'found', aevCounterpart)];
    mocks.connected = { xtmone: false, openaev: true, opencrq: false };
    const { user } = testRender(<XtmEmblem products={xtmProductsFor('System')} objectId="sys-1" />);
    await user.click(await screen.findByRole('button', { name: 'Across the XTM Platform' }));
    await screen.findByTestId('xtm-surface');
    expect(screen.queryByTestId('xtmone-section')).not.toBeInTheDocument();
    expect(screen.queryByTestId('opencrq-section')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /^Connect/ })).not.toBeInTheDocument();
  });

  it('a product without the lookup (not supported) is not listed, never "Not found"', async () => {
    // No result at all for opencrq: an older OpenCRQ answered 404, the server gives no entry.
    mocks.results = [result('sys-1', 'openaev', 'found', aevCounterpart), result('sys-1', 'xtmone', 'not_found')];
    const { user } = testRender(<XtmEmblem products={xtmProductsFor('System')} objectId="sys-1" />);
    await user.click(await screen.findByRole('button', { name: 'Across the XTM Platform' }));
    await screen.findByTestId('xtm-surface');
    expect(screen.queryByTestId('opencrq-section')).not.toBeInTheDocument();
  });

  it('nothing to show (nothing connected, no right to connect): no emblem', async () => {
    mocks.granted = false;
    mocks.connected = { xtmone: false, openaev: false, opencrq: false };
    testRender(<XtmEmblem products={xtmProductsFor('System')} objectId="sys-1" />);
    await waitFor(() => expect(mocks.calls).toHaveLength(1));
    await new Promise((resolve) => {
      setTimeout(resolve, 20);
    });
    expect(screen.queryByTestId('xtm-emblem')).not.toBeInTheDocument();
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(0);
  });
});

describe('XtmRowMark behind the flag', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.flag = true;
    mocks.connected = { xtmone: true, openaev: true, opencrq: true };
    mocks.results = [];
    mocks.calls = [];
  });

  it('no row mark and no call while the flag is off', async () => {
    mocks.flag = false;
    mocks.results = [result('vuln-1', 'openaev', 'found', aevCounterpart)];
    testRender(<XtmRowMark product={OPENAEV_PRODUCT} objectId="vuln-1" />);
    await new Promise((resolve) => {
      setTimeout(resolve, 60);
    });
    expect(screen.queryByTestId('openaev-row-mark')).not.toBeInTheDocument();
    expect(mocks.calls).toHaveLength(0);
  });

  it('is a link-role span, never an anchor inside the row link, and opens the product in a new tab', async () => {
    mocks.results = [result('vuln-1', 'openaev', 'found', aevCounterpart)];
    const opened = vi.spyOn(window, 'open').mockImplementation(() => null);
    testRender(<XtmRowMark product={OPENAEV_PRODUCT} objectId="vuln-1" />);
    const mark = await screen.findByTestId('openaev-row-mark');
    expect(mark.tagName).toBe('SPAN');
    expect(mark).toHaveAttribute('role', 'link');
    expect(mark).not.toHaveAttribute('href');
    mark.click();
    expect(opened).toHaveBeenCalledWith('https://aev.example/admin/assets/asset-1', '_blank', 'noopener,noreferrer');
    opened.mockRestore();
  });
});

describe('safeCounterpartUrl', () => {
  it('keeps http(s) addresses only', () => {
    expect(safeCounterpartUrl('https://aev.example/a')).toBe('https://aev.example/a');
    expect(safeCounterpartUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeCounterpartUrl('')).toBeUndefined();
    expect(safeCounterpartUrl(null)).toBeUndefined();
  });
});
