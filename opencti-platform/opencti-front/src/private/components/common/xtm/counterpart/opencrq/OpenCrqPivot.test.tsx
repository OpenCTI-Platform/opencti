import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import OpenCrqPivot from './OpenCrqPivot';
import OpenCrqRowMark from './OpenCrqRowMark';
import { OPENCRQ_FACTS, previewFactsOf } from '../core/counterpartFacts';
import { XTM_CONNECT_DOC_URL } from '../core/xtmConnect';
import { resetXtmCounterpartCache } from '../core/useXtmCounterparts';

type Result = { id: string; product: string; status: string; counterpart: Record<string, unknown> | null };

const mocks = vi.hoisted(() => ({
  connected: { openaev: true, opencrq: true } as Record<string, boolean>,
  results: [] as Result[],
  fail: false,
  lookups: 0,
  granted: true,
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has the object ids.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      if (!('ids' in variables)) {
        return Promise.resolve({
          xtmConnections: Object.entries(mocks.connected).map(([product, connected]) => ({ product, connected })),
        });
      }
      mocks.lookups += 1;
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      const ids = variables.ids as string[];
      return Promise.resolve({ xtmCounterpartsOf: mocks.results.filter((r) => ids.includes(r.id)).map((r) => ({ ...r, source_id: r.id })) });
    },
  }),
}));

vi.mock('../../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../utils/hooks/useGranted')>()),
  default: () => mocks.granted,
}));

const crq = {
  key: 'CVE-2024-3400',
  product: 'opencrq',
  object_id: 'vuln-9',
  object_type: 'Vulnerability',
  object_name: 'PAN-OS GlobalProtect',
  object_url: 'https://crq.example/vulnerabilities/vuln-9',
  facts: [] as Array<{ key: string; value: string }>,
};
const aev = { ...crq, product: 'openaev', object_id: 'aev-1', object_url: 'https://aev.example/admin/vulnerabilities/aev-1' };
const result = (id: string, product: string, status: string, counterpart: Record<string, unknown> | null = null): Result => ({
  id, product, status, counterpart,
});

describe('OpenCRQ pivots', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = { openaev: true, opencrq: true };
    mocks.results = [];
    mocks.fail = false;
    mocks.lookups = 0;
    mocks.granted = true;
  });

  it('found: an active icon-only link to the OpenCRQ counterpart', async () => {
    mocks.results = [result('vuln-1', 'openaev', 'found', aev), result('vuln-1', 'opencrq', 'found', crq)];
    testRender(<OpenCrqPivot objectId="vuln-1" />);
    const emblem = await screen.findByTestId('opencrq-emblem');
    expect(emblem).toHaveAttribute('href', crq.object_url);
    expect(emblem).toHaveAttribute('aria-label', 'Open in OpenCRQ');
    expect(emblem).not.toHaveTextContent('Open in OpenCRQ');
  });

  it('connected, not found: a greyed focusable emblem named "Not found in OpenCRQ"', async () => {
    mocks.results = [result('vuln-1', 'openaev', 'found', aev), result('vuln-1', 'opencrq', 'not_found')];
    testRender(<OpenCrqPivot objectId="vuln-1" />);
    const emblem = await screen.findByTestId('opencrq-emblem');
    expect(emblem).toHaveAttribute('aria-label', 'Not found in OpenCRQ');
    expect(emblem).toHaveAttribute('aria-disabled', 'true');
    expect(emblem).toHaveAttribute('data-status', 'no_match');
  });

  it('unavailable: a greyed "OpenCRQ is unavailable", OpenAEV unaffected', async () => {
    mocks.results = [result('vuln-1', 'openaev', 'found', aev), result('vuln-1', 'opencrq', 'unavailable')];
    testRender(<OpenCrqPivot objectId="vuln-1" />);
    const emblem = await screen.findByTestId('opencrq-emblem');
    expect(emblem).toHaveAttribute('aria-label', 'OpenCRQ is unavailable');
    expect(emblem).toHaveAttribute('data-status', 'unavailable');
  });

  it('draws nothing for an object type OpenCRQ does not hold (not_supported)', async () => {
    mocks.results = [result('ap-1', 'opencrq', 'not_supported')];
    testRender(<OpenCrqPivot objectId="ap-1" />);
    await waitFor(() => expect(mocks.lookups).toBe(1));
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('opencrq-emblem')).not.toBeInTheDocument();
  });

  it('not connected, configurer: a greyed emblem "Connect OpenCRQ" linking to the documentation', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    testRender(<OpenCrqPivot objectId="sys-1" />);
    const emblem = await screen.findByTestId('opencrq-emblem');
    expect(emblem).toHaveAttribute('aria-label', 'Connect OpenCRQ');
    expect(emblem).toHaveAttribute('href', XTM_CONNECT_DOC_URL);
    expect(mocks.lookups).toBe(0);
  });

  it('not connected, read-only user: "OpenCRQ is not connected", no link', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    mocks.granted = false;
    testRender(<OpenCrqPivot objectId="sys-1" />);
    const emblem = await screen.findByTestId('opencrq-emblem');
    expect(emblem).toHaveAttribute('aria-label', 'OpenCRQ is not connected');
    expect(emblem).not.toHaveAttribute('href');
  });

  it('marks a list row on a match only, in one batched lookup shared with OpenAEV', async () => {
    mocks.results = [result('sys-1', 'opencrq', 'found', { ...crq, key: 'srv-01', object_type: 'Asset' }), result('sys-2', 'opencrq', 'not_found')];
    testRender(
      <>
        <OpenCrqRowMark objectId="sys-1" />
        <OpenCrqRowMark objectId="sys-2" />
      </>,
    );
    expect(await screen.findByTestId('opencrq-row-mark')).toHaveAttribute('href', crq.object_url);
    await waitFor(() => expect(screen.getAllByTestId('opencrq-row-mark')).toHaveLength(1));
    expect(mocks.lookups).toBe(1);
  });
});

describe('previewFactsOf', () => {
  const format = { t_i18n: (m: string) => m, count: (v: number) => `${v}`, money: (v: number) => `${v} EUR`, date: (v: string) => v.slice(0, 10) };
  it('keeps the known OpenCRQ facts in display order, wrong shapes and unknown keys dropped', () => {
    expect(previewFactsOf([
      { key: 'fix_value', value: '10' },
      { key: 'risk_scenarios', value: '1' },
      { key: 'annual_loss', value: 'not a number' },
      { key: 'unknown', value: '3' },
    ], OPENCRQ_FACTS, format)).toEqual([
      { label: 'Risk scenarios', value: '1' },
      { label: 'Loss avoided by fixing', value: '10 EUR' },
    ]);
  });
  it('answers no fact for a counterpart without facts (a user without rights there)', () => {
    expect(previewFactsOf([], OPENCRQ_FACTS, format)).toEqual([]);
    expect(previewFactsOf(null, OPENCRQ_FACTS, format)).toEqual([]);
  });
});
