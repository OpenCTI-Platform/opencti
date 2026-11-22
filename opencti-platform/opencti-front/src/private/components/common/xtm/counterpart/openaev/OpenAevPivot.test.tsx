import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import OpenAevPivot from './OpenAevPivot';
import { XTM_CONNECT_DOC_URL } from '../core/xtmConnect';
import { XTM_PIVOT_COMPACT_QUERY } from '../core/useCompactPivot';
import { resetXtmCounterpartCache } from '../core/useXtmCounterparts';

type Result = { id: string; product: string; status: string; counterpart: Record<string, unknown> | null };

const mocks = vi.hoisted(() => ({
  connected: true,
  granted: true,
  results: [] as Result[],
  fail: false,
  connectionsFail: false,
  calls: [] as Array<Record<string, unknown>>,
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has the object ids.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      const isLookup = 'ids' in variables;
      mocks.calls.push({ isLookup, variables });
      if (!isLookup) {
        if (mocks.connectionsFail) return Promise.reject(new Error('unreachable'));
        return Promise.resolve({ xtmConnections: [{ product: 'openaev', connected: mocks.connected }] });
      }
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      const ids = variables.ids as string[];
      return Promise.resolve({ xtmCounterpartsOf: mocks.results.filter((r) => ids.includes(r.id)) });
    },
  }),
}));

vi.mock('../../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../utils/hooks/useGranted')>()),
  default: () => mocks.granted,
}));

const counterpart = {
  key: 'T1059',
  product: 'openaev',
  object_id: 'ap-1',
  object_type: 'AttackPattern',
  object_name: 'Command and Scripting Interpreter',
  object_url: 'https://aev.example/admin/attack_patterns/ap-1',
  facts: [],
};
const found = (id: string): Result => ({ id, product: 'openaev', status: 'found', counterpart });
const answered = (id: string, status: string): Result => ({ id, product: 'openaev', status, counterpart: null });

describe('OpenAevPivot', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.granted = true;
    mocks.results = [];
    mocks.fail = false;
    mocks.connectionsFail = false;
    mocks.calls = [];
  });

  it('links to the OpenAEV counterpart when connected with a match', async () => {
    mocks.results = [found('ap-octi-1')];
    testRender(<OpenAevPivot objectId="ap-octi-1" />);
    const link = await screen.findByRole('link', { name: 'Open in OpenAEV' });
    expect(link).toHaveAttribute('href', counterpart.object_url);
    expect(link).toHaveAttribute('target', '_blank');
    // A framed text button, like the other text actions of the header, never an icon alone.
    expect(link).toHaveTextContent('Open in OpenAEV');
  });

  it('draws nothing when OpenAEV is connected and does not hold the object', async () => {
    mocks.results = [answered('vuln-1', 'not_found')];
    testRender(<OpenAevPivot objectId="vuln-1" />);
    await waitFor(() => expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(1));
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('openaev-pivot')).not.toBeInTheDocument();
    expect(screen.queryByText('Not in OpenAEV')).not.toBeInTheDocument();
  });

  it('shows a disabled muted "OpenAEV is unavailable" when OpenAEV could not answer, and asks again next time', async () => {
    mocks.results = [answered('sys-1', 'unavailable')];
    const { unmount } = testRender(<OpenAevPivot objectId="sys-1" />);
    const pivot = await screen.findByRole('button', { name: 'OpenAEV is unavailable' });
    expect(pivot).toBeDisabled();
    expect(pivot).toHaveAttribute('data-status', 'unavailable');
    unmount();
    // Never cached: the next render asks again and shows the answer.
    mocks.results = [found('sys-1')];
    testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('link', { name: 'Open in OpenAEV' })).toBeInTheDocument();
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(2);
  });

  it('shows "OpenAEV is unavailable" on a failed lookup, never a page error and never "Not in OpenAEV"', async () => {
    mocks.fail = true;
    testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is unavailable' })).toBeDisabled();
    expect(screen.queryByTestId('openaev-pivot')).toHaveAttribute('data-status', 'unavailable');
  });

  it('draws nothing when the object has no entry (no key, not readable) or OpenAEV has no such lookup', async () => {
    mocks.results = [answered('ap-2', 'not_supported')];
    testRender(
      <>
        <OpenAevPivot objectId="unreadable-1" />
        <OpenAevPivot objectId="ap-2" />
      </>,
    );
    await waitFor(() => expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(1));
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('openaev-pivot')).not.toBeInTheDocument();
  });

  it('offers to connect OpenAEV to a user who can configure the platform', async () => {
    mocks.connected = false;
    testRender(<OpenAevPivot objectId="sys-1" />);
    const link = await screen.findByRole('link', { name: 'Connect OpenAEV' });
    expect(link).toHaveAttribute('href', XTM_CONNECT_DOC_URL);
    expect(link).toHaveTextContent('Connect OpenAEV');
    // Not connected: no counterpart lookup is sent.
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(0);
  });

  it('shows a read-only hint to a user without the right to configure', async () => {
    mocks.connected = false;
    mocks.granted = false;
    testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is not connected' })).toBeDisabled();
    expect(screen.queryByRole('link', { name: 'Connect OpenAEV' })).not.toBeInTheDocument();
  });

  it('a failed connections query is unavailable, never "not connected", and is not cached', async () => {
    mocks.connectionsFail = true;
    const { unmount } = testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is unavailable' })).toBeDisabled();
    expect(screen.queryByRole('link', { name: 'Connect OpenAEV' })).not.toBeInTheDocument();
    unmount();
    mocks.connectionsFail = false;
    mocks.results = [found('sys-1')];
    testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('link', { name: 'Open in OpenAEV' })).toBeInTheDocument();
  });

  it('batches the ids of every object asked in the same tick into a single lookup', async () => {
    mocks.results = [found('ap-octi-1'), answered('vuln-1', 'not_found')];
    testRender(
      <>
        <OpenAevPivot objectId="ap-octi-1" />
        <OpenAevPivot objectId="vuln-1" />
      </>,
    );
    await waitFor(() => expect(screen.getAllByTestId('openaev-pivot')).toHaveLength(1));
    const lookups = mocks.calls.filter((c) => c.isLookup);
    expect(lookups).toHaveLength(1);
    expect(lookups[0].variables).toEqual({ ids: ['ap-octi-1', 'vuln-1'] });
  });

  describe('below 1280 px', () => {
    const originalMatchMedia = window.matchMedia;
    beforeEach(() => {
      window.matchMedia = ((query: string) => ({
        matches: query === XTM_PIVOT_COMPACT_QUERY,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      })) as typeof window.matchMedia;
    });
    afterEach(() => {
      window.matchMedia = originalMatchMedia;
    });

    it('renders the match as an icon-only link named "Open in OpenAEV", so a long title keeps its room', async () => {
      mocks.results = [found('ap-octi-1')];
      testRender(<OpenAevPivot objectId="ap-octi-1" />);
      const link = await screen.findByRole('link', { name: 'Open in OpenAEV' });
      expect(link).toHaveAttribute('href', counterpart.object_url);
      expect(link).not.toHaveTextContent('Open in OpenAEV');
    });

    it('renders the connect call to action as an icon-only link named "Connect OpenAEV"', async () => {
      mocks.connected = false;
      testRender(<OpenAevPivot objectId="sys-1" />);
      const link = await screen.findByRole('link', { name: 'Connect OpenAEV' });
      expect(link).toHaveAttribute('href', XTM_CONNECT_DOC_URL);
      expect(link).not.toHaveTextContent('Connect OpenAEV');
    });
  });
});
