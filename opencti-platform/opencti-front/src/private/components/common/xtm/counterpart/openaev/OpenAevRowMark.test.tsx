import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import OpenAevRowMark from './OpenAevRowMark';
import { resetXtmCounterpartCache, XTM_COUNTERPART_MAX_IDS, lookupXtmCounterpartsOf } from '../core/useXtmCounterparts';

type Result = { id: string; product: string; status: string; counterpart: Record<string, unknown> | null };

const mocks = vi.hoisted(() => ({
  connected: true,
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
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected }] });
      }
      const ids = variables.ids as string[];
      return Promise.resolve({ xtmCounterpartsOf: mocks.results.filter((r) => ids.includes(r.id)).map((r) => ({ ...r, source_id: r.id })) });
    },
  }),
}));

// The row marks are behind the dedicated feature flag XTM_COUNTERPARTS: these tests run with it on.
vi.mock('../../../../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (id: string) => id === 'XTM_COUNTERPARTS' }),
}));

const counterpart = {
  key: 'CVE-2024-0001',
  product: 'openaev',
  object_id: 'v-1',
  object_type: 'Vulnerability',
  object_name: 'CVE-2024-0001',
  object_url: 'https://aev.example/admin/vulnerabilities/v-1',
  facts: [],
};

describe('OpenAevRowMark', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.results = [];
    mocks.calls = [];
  });

  it('links to the OpenAEV counterpart of a row', async () => {
    mocks.results = [{ id: 'vuln-1', product: 'openaev', status: 'found', counterpart }];
    testRender(<OpenAevRowMark objectId="vuln-1" />);
    const link = await screen.findByRole('link', { name: 'Open in OpenAEV' });
    expect(link).toHaveAttribute('href', counterpart.object_url);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('data-testid', 'openaev-row-mark');
  });

  it('draws nothing without a match, and nothing when OpenAEV is unavailable', async () => {
    mocks.results = [
      { id: 'vuln-2', product: 'openaev', status: 'not_found', counterpart: null },
      { id: 'vuln-3', product: 'openaev', status: 'unavailable', counterpart: null },
    ];
    const { container } = testRender(
      <>
        <OpenAevRowMark objectId="vuln-2" />
        <OpenAevRowMark objectId="vuln-3" />
      </>,
    );
    await waitFor(() => expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(1));
    await new Promise((resolve) => {
      setTimeout(resolve, 20);
    });
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(container.querySelector('svg')).toBeNull();
  });

  it('draws nothing and sends no lookup when OpenAEV is not connected', async () => {
    mocks.connected = false;
    testRender(<OpenAevRowMark objectId="sys-1" />);
    await waitFor(() => expect(mocks.calls).toHaveLength(1));
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(0);
  });

  it('splits a batch larger than the server limit', async () => {
    const ids = Array.from({ length: XTM_COUNTERPART_MAX_IDS + 5 }, (_, i) => `obj-${i}`);
    await Promise.all(ids.map((id) => lookupXtmCounterpartsOf(id)));
    const lookups = mocks.calls.filter((c) => c.isLookup);
    expect(lookups).toHaveLength(2);
    expect((lookups[0].variables as { ids: string[] }).ids).toHaveLength(XTM_COUNTERPART_MAX_IDS);
    expect((lookups[1].variables as { ids: string[] }).ids).toHaveLength(5);
  });
});
