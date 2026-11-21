import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import OpenAevCard from './OpenAevCard';
import { resetXtmCounterpartCache } from '../core/useXtmCounterparts';

type Result = { id: string; product: string; status: string; counterpart: Record<string, unknown> | null };

const mocks = vi.hoisted(() => ({
  connected: true,
  results: [] as Result[],
  fail: false,
  lookups: 0,
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has the object ids.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      if (!('ids' in variables)) {
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected }] });
      }
      mocks.lookups += 1;
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      return Promise.resolve({ xtmCounterpartsOf: mocks.results });
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
const found = (c: Record<string, unknown> = counterpart): Result => ({ id: 'obj-1', product: 'openaev', status: 'found', counterpart: c });
const answered = (status: string): Result => ({ id: 'obj-1', product: 'openaev', status, counterpart: null });

const settle = () => new Promise((resolve) => {
  setTimeout(resolve, 60);
});

describe('OpenAevCard', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.results = [];
    mocks.fail = false;
    mocks.lookups = 0;
  });

  it('shows the counterpart and the shared identifier on a match, with no link of its own (the hero pivot is the single one)', async () => {
    mocks.results = [found()];
    testRender(<OpenAevCard objectId="obj-1" />);
    expect(await screen.findByText('In OpenAEV')).toBeInTheDocument();
    expect(screen.getByText(counterpart.object_name)).toBeInTheDocument();
    expect(screen.getByText('Shared identifier: CVE-2024-3400')).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Open in OpenAEV' })).not.toBeInTheDocument();
  });

  it('shows a muted "Not in OpenAEV" without a link when OpenAEV answered without a match', async () => {
    mocks.results = [answered('not_found')];
    testRender(<OpenAevCard objectId="obj-1" />);
    expect(await screen.findByText('Not in OpenAEV')).toBeInTheDocument();
    expect(screen.queryByText(/Shared identifier/)).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Open in OpenAEV' })).not.toBeInTheDocument();
  });

  it('draws nothing when OpenAEV is not connected (the hero carries the call to action)', async () => {
    mocks.connected = false;
    testRender(<OpenAevCard objectId="obj-1" />);
    await waitFor(() => expect(mocks.lookups).toBe(0));
    await settle();
    expect(screen.queryByTestId('openaev-card')).not.toBeInTheDocument();
    expect(mocks.lookups).toBe(0);
  });

  it('draws nothing when OpenAEV is unavailable or the lookup failed (the hero shows it), never "Not in OpenAEV"', async () => {
    mocks.results = [answered('unavailable')];
    const { unmount } = testRender(<OpenAevCard objectId="obj-1" />);
    await settle();
    expect(screen.queryByTestId('openaev-card')).not.toBeInTheDocument();
    unmount();
    resetXtmCounterpartCache();
    mocks.fail = true;
    testRender(<OpenAevCard objectId="obj-1" />);
    await settle();
    expect(screen.queryByTestId('openaev-card')).not.toBeInTheDocument();
    expect(screen.queryByText('Not in OpenAEV')).not.toBeInTheDocument();
  });

  it('draws nothing for an object with no entry or a route OpenAEV does not support', async () => {
    mocks.results = [answered('not_supported')];
    testRender(
      <>
        <OpenAevCard objectId="obj-1" />
        <OpenAevCard objectId="no-key-1" />
      </>,
    );
    await settle();
    expect(screen.queryByTestId('openaev-card')).not.toBeInTheDocument();
  });

  it('shows the key facts of the counterpart, plural-aware, unknown ones dropped', async () => {
    mocks.results = [found({
      ...counterpart,
      facts: [
        { key: 'findings', value: '5' },
        { key: 'affected_assets', value: '1' },
        { key: 'unknown_fact', value: '9' },
        { key: 'simulations', value: 'not a number' },
      ],
    })];
    testRender(<OpenAevCard objectId="obj-1" />);
    expect(await screen.findByTestId('openaev-card-facts')).toHaveTextContent('5 findings · 1 affected asset');
  });

  it('shows the simulations of a scenario and the date of the latest one, with no STIX id as identifier', async () => {
    mocks.results = [found({
      ...counterpart,
      key: 'intrusion-set--4f7e2a8c-1c5b-4b0e-9a8e-0c2d3e4f5a6b',
      facts: [{ key: 'simulations', value: '1' }, { key: 'last_simulation', value: '2026-11-17T09:30:00Z' }],
    })];
    testRender(<OpenAevCard objectId="obj-1" />);
    const facts = await screen.findByTestId('openaev-card-facts');
    expect(facts).toHaveTextContent('1 simulation');
    expect(facts).toHaveTextContent('Last simulation:');
    expect(screen.queryByText(/Shared identifier/)).not.toBeInTheDocument();
  });

  it('draws no facts line when the counterpart has none (a user without rights in OpenAEV)', async () => {
    mocks.results = [found()];
    testRender(<OpenAevCard objectId="obj-1" />);
    expect(await screen.findByText(counterpart.object_name)).toBeInTheDocument();
    expect(screen.queryByTestId('openaev-card-facts')).not.toBeInTheDocument();
  });
});
