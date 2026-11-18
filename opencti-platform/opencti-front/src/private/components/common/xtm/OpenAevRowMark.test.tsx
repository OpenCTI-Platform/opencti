import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import OpenAevRowMark from './OpenAevRowMark';
import { resetXtmCounterpartCache, XTM_COUNTERPART_MAX_KEYS, lookupXtmCounterpart } from './useXtmCounterparts';

const mocks = vi.hoisted(() => ({
  connected: true,
  counterparts: [] as Array<Record<string, string | null>>,
  calls: [] as Array<Record<string, unknown>>,
}));

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      const isLookup = 'keys' in variables;
      mocks.calls.push({ isLookup, variables });
      if (!isLookup) {
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected, url: null }] });
      }
      return Promise.resolve({ xtmCounterparts: mocks.counterparts });
    },
  }),
}));

const counterpart = {
  key: 'CVE-2024-0001',
  product: 'openaev',
  object_id: 'v-1',
  object_type: 'Vulnerability',
  object_name: 'CVE-2024-0001',
  object_url: 'https://aev.example/admin/vulnerabilities/v-1',
};

describe('OpenAevRowMark', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.counterparts = [];
    mocks.calls = [];
  });

  it('links to the OpenAEV counterpart of a row', async () => {
    mocks.counterparts = [counterpart];
    testRender(<OpenAevRowMark kind="VULNERABILITY" counterpartKey="cve-2024-0001" />);
    const link = await screen.findByRole('link', { name: 'Open in OpenAEV' });
    expect(link).toHaveAttribute('href', counterpart.object_url);
    expect(link).toHaveAttribute('target', '_blank');
  });

  it('draws nothing without a match', async () => {
    const { container } = testRender(<OpenAevRowMark kind="VULNERABILITY" counterpartKey="CVE-2024-9999" />);
    await waitFor(() => expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(1));
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(container.querySelector('svg')).toBeNull();
  });

  it('draws nothing and sends no lookup when OpenAEV is not connected', async () => {
    mocks.connected = false;
    testRender(<OpenAevRowMark kind="ASSET" counterpartKey="srv-01" />);
    await waitFor(() => expect(mocks.calls).toHaveLength(1));
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(0);
  });

  it('splits a batch larger than the server limit', async () => {
    const keys = Array.from({ length: XTM_COUNTERPART_MAX_KEYS + 5 }, (_, i) => `T${1000 + i}`);
    await Promise.all(keys.map((key) => lookupXtmCounterpart('ATTACK_PATTERN', key)));
    const lookups = mocks.calls.filter((c) => c.isLookup);
    expect(lookups).toHaveLength(2);
    expect((lookups[0].variables as { keys: string[] }).keys).toHaveLength(XTM_COUNTERPART_MAX_KEYS);
    expect((lookups[1].variables as { keys: string[] }).keys).toHaveLength(5);
  });
});
