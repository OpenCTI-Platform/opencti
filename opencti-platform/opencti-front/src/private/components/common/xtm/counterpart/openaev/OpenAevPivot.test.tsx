import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import OpenAevPivot from './OpenAevPivot';
import { XTM_CONNECT_DOC_URL } from '../core/xtmConnect';
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

describe('OpenAevPivot (Contract v3: icon-only emblem)', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = true;
    mocks.granted = true;
    mocks.results = [];
    mocks.fail = false;
    mocks.connectionsFail = false;
    mocks.calls = [];
  });

  it('found: an active icon-only link named "Open in OpenAEV", no text', async () => {
    mocks.results = [found('ap-octi-1')];
    testRender(<OpenAevPivot objectId="ap-octi-1" />);
    const link = await screen.findByRole('link', { name: 'Open in OpenAEV' });
    expect(link).toHaveAttribute('href', counterpart.object_url);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('data-status', 'match');
    expect(link).not.toHaveTextContent('Open in OpenAEV');
  });

  it('connected, not found: a greyed emblem, still focusable, named "Not found in OpenAEV"', async () => {
    mocks.results = [answered('vuln-1', 'not_found')];
    testRender(<OpenAevPivot objectId="vuln-1" />);
    const emblem = await screen.findByRole('button', { name: 'Not found in OpenAEV' });
    expect(emblem).toHaveAttribute('aria-disabled', 'true');
    expect(emblem).not.toBeDisabled();
    expect(emblem).toHaveAttribute('data-status', 'no_match');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('unavailable: a greyed "OpenAEV is unavailable", and asks again next time', async () => {
    mocks.results = [answered('sys-1', 'unavailable')];
    const { unmount } = testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is unavailable' })).toHaveAttribute('aria-disabled', 'true');
    unmount();
    mocks.results = [found('sys-1')];
    testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('link', { name: 'Open in OpenAEV' })).toBeInTheDocument();
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(2);
  });

  it('a failed lookup is unavailable, never a page error', async () => {
    mocks.fail = true;
    testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is unavailable' })).toHaveAttribute('data-status', 'unavailable');
  });

  it('draws nothing for an object OpenAEV has no lookup for (not_supported) or no entry', async () => {
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
    expect(screen.queryByTestId('openaev-emblem')).not.toBeInTheDocument();
  });

  it('not connected, configurer: a greyed emblem linking to the connection documentation', async () => {
    mocks.connected = false;
    testRender(<OpenAevPivot objectId="sys-1" />);
    const link = await screen.findByRole('link', { name: 'Connect OpenAEV' });
    expect(link).toHaveAttribute('href', XTM_CONNECT_DOC_URL);
    expect(link).toHaveAttribute('data-status', 'not_connected');
    expect(link).not.toHaveTextContent('Connect OpenAEV');
    expect(mocks.calls.filter((c) => c.isLookup)).toHaveLength(0);
  });

  it('not connected, read-only user: a greyed emblem named "OpenAEV is not connected", no link', async () => {
    mocks.connected = false;
    mocks.granted = false;
    testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is not connected' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('a failed connections query is unavailable, never "not connected", and is not cached', async () => {
    mocks.connectionsFail = true;
    const { unmount } = testRender(<OpenAevPivot objectId="sys-1" />);
    expect(await screen.findByRole('button', { name: 'OpenAEV is unavailable' })).toBeInTheDocument();
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
    await waitFor(() => expect(screen.getAllByTestId('openaev-emblem')).toHaveLength(2));
    const lookups = mocks.calls.filter((c) => c.isLookup);
    expect(lookups).toHaveLength(1);
    expect(lookups[0].variables).toEqual({ ids: ['ap-octi-1', 'vuln-1'] });
  });
});
