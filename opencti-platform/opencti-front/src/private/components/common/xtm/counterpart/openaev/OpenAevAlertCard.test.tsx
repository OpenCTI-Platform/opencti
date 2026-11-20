import React from 'react';
import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import OpenAevAlertCard from './OpenAevAlertCard';
import { resetXtmCounterpartCache } from '../core/useXtmCounterparts';

const mocks = vi.hoisted(() => ({
  connected: true,
  counterparts: [] as Array<Record<string, string | null>>,
  fail: false,
  lookups: [] as Array<Record<string, unknown>>,
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has a kind and keys.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      if (!('keys' in variables)) {
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected }] });
      }
      mocks.lookups.push(variables);
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      return Promise.resolve({ xtmCounterparts: mocks.counterparts });
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
};

const settle = () => new Promise((resolve) => {
  setTimeout(resolve, 80);
});

describe('OpenAevAlertCard', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.counterparts = [];
    mocks.fail = false;
    mocks.lookups = [];
  });

  it('shows the inject the alert answered with "Investigate in OpenAEV" on a match', async () => {
    mocks.counterparts = [counterpart];
    testRender(<OpenAevAlertCard alertLinks={[` ${ALERT_LINK} `, 'https://vendor.example.com/advisory', null]} />);
    expect(await screen.findByText('In OpenAEV')).toBeInTheDocument();
    expect(screen.getByText(counterpart.object_name)).toBeInTheDocument();
    expect(screen.getByText(`Alert expected by this inject: ${ALERT_LINK}`)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Investigate in OpenAEV' })).toHaveAttribute('href', counterpart.object_url);
    // Every link of the incident is asked in one batched lookup, case kept.
    expect(mocks.lookups).toHaveLength(1);
    expect(mocks.lookups[0]).toEqual({ kind: 'ALERT', keys: [ALERT_LINK, 'https://vendor.example.com/advisory'] });
  });

  it('draws nothing when connected without a match', async () => {
    testRender(<OpenAevAlertCard alertLinks={[ALERT_LINK]} />);
    await settle();
    expect(mocks.lookups).toHaveLength(1);
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });

  it('draws nothing and asks nothing when OpenAEV is not connected', async () => {
    mocks.connected = false;
    testRender(<OpenAevAlertCard alertLinks={[ALERT_LINK]} />);
    await settle();
    expect(mocks.lookups).toHaveLength(0);
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });

  it('asks nothing for references that are not links', async () => {
    testRender(<OpenAevAlertCard alertLinks={['ALERT-123', '', undefined]} />);
    await settle();
    expect(mocks.lookups).toHaveLength(0);
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });

  it('degrades to nothing on a lookup error, never a page error', async () => {
    mocks.fail = true;
    testRender(<OpenAevAlertCard alertLinks={[ALERT_LINK]} />);
    await settle();
    expect(screen.queryByTestId('openaev-alert-card')).not.toBeInTheDocument();
  });
});
