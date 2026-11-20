import React from 'react';
import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import OpenAevAlertCard from './OpenAevAlertCard';
import { resetXtmCounterpartCache } from '../core/useXtmCounterparts';

type Result = { id: string; product: string; status: string; counterpart: Record<string, unknown> | null };

const mocks = vi.hoisted(() => ({
  connected: true,
  results: [] as Result[],
  fail: false,
  lookups: [] as Array<Record<string, unknown>>,
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has the object ids.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      if (!('ids' in variables)) {
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected }] });
      }
      mocks.lookups.push(variables);
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      return Promise.resolve({ xtmCounterpartsOf: mocks.results });
    },
  }),
}));

const ALERT_LINK = 'https://edr.example.com/alerts/AbC-123';

const counterpart = {
  key: ALERT_LINK,
  product: 'openaev',
  object_id: 'inject-1',
  object_type: 'Inject',
  object_name: 'Execute encoded PowerShell',
  object_url: 'https://aev.example/admin/simulations/exercise-1/injects/inject-1',
  facts: [],
};

const settle = () => new Promise((resolve) => {
  setTimeout(resolve, 80);
});

describe('OpenAevAlertCard', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.results = [];
    mocks.fail = false;
    mocks.lookups = [];
  });

  it('shows the inject the alert answered with "Investigate in OpenAEV" on a match, asking by the incident id', async () => {
    mocks.results = [{ id: 'incident-1', product: 'openaev', status: 'found', counterpart }];
    testRender(<OpenAevAlertCard objectId="incident-1" />);
    expect(await screen.findByText('In OpenAEV')).toBeInTheDocument();
    expect(screen.getByText(counterpart.object_name)).toBeInTheDocument();
    expect(screen.getByText(`Alert expected by this inject: ${ALERT_LINK}`)).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Investigate in OpenAEV' });
    expect(link).toHaveAttribute('href', counterpart.object_url);
    // The links are read on the server: the client sends the id alone.
    expect(mocks.lookups).toEqual([{ ids: ['incident-1'] }]);
  });

  it('draws nothing when connected without a match', async () => {
    mocks.results = [{ id: 'incident-1', product: 'openaev', status: 'not_found', counterpart: null }];
    testRender(<OpenAevAlertCard objectId="incident-1" />);
    await settle();
    expect(mocks.lookups).toHaveLength(1);
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });

  it('draws nothing and asks nothing when OpenAEV is not connected', async () => {
    mocks.connected = false;
    testRender(<OpenAevAlertCard objectId="incident-1" />);
    await settle();
    expect(mocks.lookups).toHaveLength(0);
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });

  it('draws nothing for an incident without alert links (no entry in the answer)', async () => {
    testRender(<OpenAevAlertCard objectId="incident-2" />);
    await settle();
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });

  it('degrades to nothing on an unavailable OpenAEV or a lookup error, never a page error', async () => {
    mocks.results = [{ id: 'incident-1', product: 'openaev', status: 'unavailable', counterpart: null }];
    const { unmount } = testRender(<OpenAevAlertCard objectId="incident-1" />);
    await settle();
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
    unmount();
    mocks.fail = true;
    testRender(<OpenAevAlertCard objectId="incident-1" />);
    await settle();
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });
});
