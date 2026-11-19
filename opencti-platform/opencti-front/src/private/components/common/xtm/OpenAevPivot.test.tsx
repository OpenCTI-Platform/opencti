import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import OpenAevPivot, { OPENAEV_CONNECT_DOC_URL } from './OpenAevPivot';
import { normaliseXtmKey, resetXtmCounterpartCache } from './useXtmCounterparts';

const mocks = vi.hoisted(() => ({
  connected: true,
  granted: true,
  counterparts: [] as Array<Record<string, string | null>>,
  fail: false,
  calls: [] as Array<Record<string, unknown>>,
}));

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has a kind and keys.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      const isLookup = 'keys' in variables;
      mocks.calls.push({ isLookup, variables });
      if (!isLookup) {
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected, url: null }] });
      }
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      return Promise.resolve({ xtmCounterparts: mocks.counterparts });
    },
  }),
}));

vi.mock('../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useGranted')>()),
  default: () => mocks.granted,
}));

const counterpart = {
  key: 'T1059',
  product: 'openaev',
  object_id: 'ap-1',
  object_type: 'AttackPattern',
  object_name: 'Command and Scripting Interpreter',
  object_url: 'https://aev.example/admin/attack_patterns/ap-1',
};

describe('OpenAevPivot', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.granted = true;
    mocks.counterparts = [];
    mocks.fail = false;
    mocks.calls = [];
  });

  it('links to the OpenAEV counterpart when connected with a match', async () => {
    mocks.counterparts = [counterpart];
    testRender(<OpenAevPivot kind="ATTACK_PATTERN" counterpartKey="t1059" />);
    const link = await screen.findByRole('link', { name: 'Open in OpenAEV' });
    expect(link).toHaveAttribute('href', counterpart.object_url);
    expect(link).toHaveAttribute('target', '_blank');
    // A framed text button, like the other text actions of the header, never an icon alone.
    expect(link).toHaveTextContent('Open in OpenAEV');
  });

  it('shows a disabled "Not in OpenAEV" when connected without a match', async () => {
    testRender(<OpenAevPivot kind="VULNERABILITY" counterpartKey="CVE-2024-0001" />);
    expect(await screen.findByRole('button', { name: 'Not in OpenAEV' })).toBeDisabled();
  });

  it('offers to connect OpenAEV to a user who can configure the platform', async () => {
    mocks.connected = false;
    testRender(<OpenAevPivot kind="ASSET" counterpartKey="srv-01" />);
    const link = await screen.findByRole('link', { name: 'Connect OpenAEV' });
    expect(link).toHaveAttribute('href', OPENAEV_CONNECT_DOC_URL);
    expect(link).toHaveTextContent('Connect OpenAEV');
    // Not connected: no counterpart lookup is sent.
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(0);
  });

  it('shows a read-only hint to a user without the right to configure', async () => {
    mocks.connected = false;
    mocks.granted = false;
    testRender(<OpenAevPivot kind="ASSET" counterpartKey="srv-01" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is not connected' })).toBeDisabled();
    expect(screen.queryByRole('link', { name: 'Connect OpenAEV' })).not.toBeInTheDocument();
  });

  it('degrades to a muted "Not in OpenAEV" on a lookup error, never a page error', async () => {
    mocks.fail = true;
    testRender(<OpenAevPivot kind="ASSET" counterpartKey="srv-01" />);
    expect(await screen.findByRole('button', { name: 'Not in OpenAEV' })).toBeDisabled();
  });

  it('batches keys of one kind into a single lookup', async () => {
    mocks.counterparts = [counterpart];
    testRender(
      <>
        <OpenAevPivot kind="ATTACK_PATTERN" counterpartKey="T1059" />
        <OpenAevPivot kind="ATTACK_PATTERN" counterpartKey="T1003" />
      </>,
    );
    await waitFor(() => expect(screen.getByRole('button', { name: 'Not in OpenAEV' })).toBeInTheDocument());
    const lookups = mocks.calls.filter((c) => c.isLookup);
    expect(lookups).toHaveLength(1);
    expect(lookups[0].variables).toEqual({ kind: 'ATTACK_PATTERN', keys: ['T1059', 'T1003'] });
  });

  it('normalises keys like the server', () => {
    expect(normaliseXtmKey('ASSET', ' SRV-01 ')).toBe('srv-01');
    expect(normaliseXtmKey('VULNERABILITY', 'cve-2024-0001')).toBe('CVE-2024-0001');
    expect(normaliseXtmKey('THREAT', 'Intrusion-Set--ABC')).toBe('intrusion-set--abc');
    expect(normaliseXtmKey('ATTACK_PATTERN', '')).toBeNull();
  });
});
