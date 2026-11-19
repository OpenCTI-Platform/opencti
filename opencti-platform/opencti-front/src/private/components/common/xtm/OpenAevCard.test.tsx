import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import OpenAevCard, { openAevCardAnchorKey } from './OpenAevCard';
import { resetXtmCounterpartCache } from './useXtmCounterparts';

const mocks = vi.hoisted(() => ({
  connected: true,
  counterparts: [] as Array<Record<string, unknown>>,
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
  facts: [] as Array<{ key: string; value: string }>,
};

describe('OpenAevCard', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.counterparts = [];
    mocks.fail = false;
    mocks.lookups = 0;
  });

  it('shows the counterpart and the shared identifier on a match, with no link of its own (the hero pivot is the single one)', async () => {
    mocks.counterparts = [counterpart];
    testRender(<OpenAevCard kind="VULNERABILITY" counterpartKey="cve-2024-3400" />);
    expect(await screen.findByText('In OpenAEV')).toBeInTheDocument();
    expect(screen.getByText(counterpart.object_name)).toBeInTheDocument();
    expect(screen.getByText('Shared identifier: CVE-2024-3400')).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open in OpenAEV' })).not.toBeInTheDocument();
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

  it('shows the key facts of the counterpart, plural-aware, unknown ones dropped', async () => {
    mocks.counterparts = [{
      ...counterpart,
      facts: [
        { key: 'findings', value: '5' },
        { key: 'affected_assets', value: '1' },
        { key: 'unknown_fact', value: '9' },
        { key: 'simulations', value: 'not a number' },
      ],
    }];
    testRender(<OpenAevCard kind="VULNERABILITY" counterpartKey="CVE-2024-3400" />);
    expect(await screen.findByTestId('openaev-card-facts')).toHaveTextContent('5 findings · 1 affected asset');
  });

  it('shows the simulations of a scenario and the date of the latest one', async () => {
    mocks.counterparts = [{
      ...counterpart,
      key: 'intrusion-set--4f7e2a8c-1c5b-4b0e-9a8e-0c2d3e4f5a6b',
      facts: [{ key: 'simulations', value: '1' }, { key: 'last_simulation', value: '2026-11-17T09:30:00Z' }],
    }];
    testRender(<OpenAevCard kind="THREAT" counterpartKey="intrusion-set--4f7e2a8c-1c5b-4b0e-9a8e-0c2d3e4f5a6b" />);
    const facts = await screen.findByTestId('openaev-card-facts');
    expect(facts).toHaveTextContent('1 simulation');
    expect(facts).toHaveTextContent('Last simulation:');
    // A STIX id means nothing to an analyst: the threat card shows no shared identifier line.
    expect(screen.queryByText(/Shared identifier/)).not.toBeInTheDocument();
  });

  it('draws no facts line when the counterpart has none', async () => {
    mocks.counterparts = [counterpart];
    testRender(<OpenAevCard kind="VULNERABILITY" counterpartKey="CVE-2024-3400" />);
    expect(await screen.findByText(counterpart.object_name)).toBeInTheDocument();
    expect(screen.queryByTestId('openaev-card-facts')).not.toBeInTheDocument();
  });

  it('degrades to "Not in OpenAEV" on a lookup error, never a page error', async () => {
    mocks.fail = true;
    testRender(<OpenAevCard kind="ASSET" counterpartKey="srv-01" />);
    expect(await screen.findByText('Not in OpenAEV')).toBeInTheDocument();
  });
});

describe('openAevCardAnchorKey', () => {
  it('places the card after the later of Details and Basic information, above Notes', () => {
    expect(openAevCardAnchorKey([
      { key: 'details' },
      { key: 'basicInformation' },
      { key: 'latestCreatedRelationships' },
      { key: 'notes' },
    ])).toBe('basicInformation');
    expect(openAevCardAnchorKey([{ key: 'basicInformation' }, { key: 'details' }, { key: 'notes' }])).toBe('details');
  });

  it('has no anchor when the layout shows neither, so the card closes the grid', () => {
    expect(openAevCardAnchorKey([{ key: 'notes' }])).toBeNull();
  });
});
