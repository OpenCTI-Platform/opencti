import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import OpenAevCard from './OpenAevCard';
import { resetXtmCounterpartCache } from './useXtmCounterparts';

const mocks = vi.hoisted(() => ({
  connected: true,
  counterparts: [] as Array<Record<string, string | null>>,
  fail: false,
  lookups: 0,
}));

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has a kind and keys.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      if (!('keys' in variables)) {
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected, url: null }] });
      }
      mocks.lookups += 1;
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      return Promise.resolve({ xtmCounterparts: mocks.counterparts });
    },
  }),
}));

const counterpart = {
  key: 'CVE-2024-3400',
  product: 'openaev',
  object_id: 'vuln-1',
  object_type: 'Vulnerability',
  object_name: 'PAN-OS GlobalProtect command injection',
  object_url: 'https://aev.example/admin/vulnerabilities/vuln-1',
};

describe('OpenAevCard', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.counterparts = [];
    mocks.fail = false;
    mocks.lookups = 0;
  });

  it('shows the counterpart, the shared identifier and a link to it on a match', async () => {
    mocks.counterparts = [counterpart];
    testRender(<OpenAevCard kind="VULNERABILITY" counterpartKey="cve-2024-3400" />);
    expect(await screen.findByText('In OpenAEV')).toBeInTheDocument();
    expect(screen.getByText(counterpart.object_name)).toBeInTheDocument();
    expect(screen.getByText('Shared identifier: CVE-2024-3400')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open in OpenAEV' })).toHaveAttribute('href', counterpart.object_url);
  });

  it('shows a muted "Not in OpenAEV" without a link when connected without a match', async () => {
    testRender(<OpenAevCard kind="ATTACK_PATTERN" counterpartKey="T1059" />);
    expect(await screen.findByText('Not in OpenAEV')).toBeInTheDocument();
    expect(screen.getByText('Shared identifier: T1059')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Open in OpenAEV' })).not.toBeInTheDocument();
  });

  it('draws nothing when OpenAEV is not connected (the hero carries the call to action)', async () => {
    mocks.connected = false;
    testRender(<OpenAevCard kind="ASSET" counterpartKey="srv-01" />);
    // Let the connection lookup settle before asserting the absence.
    await waitFor(() => expect(mocks.lookups).toBe(0));
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('openaev-card')).not.toBeInTheDocument();
    expect(mocks.lookups).toBe(0);
  });

  it('degrades to "Not in OpenAEV" on a lookup error, never a page error', async () => {
    mocks.fail = true;
    testRender(<OpenAevCard kind="ASSET" counterpartKey="srv-01" />);
    expect(await screen.findByText('Not in OpenAEV')).toBeInTheDocument();
  });
});
