import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import { formatOpenCrqFacts, OpenCrqCard, OpenCrqPivot, OpenCrqRowMark } from './OpenCrq';
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
      return Promise.resolve({ xtmCounterpartsOf: mocks.results.filter((r) => ids.includes(r.id)) });
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

  it('opens the OpenCRQ counterpart when both products hold the object', async () => {
    mocks.results = [result('vuln-1', 'openaev', 'found', aev), result('vuln-1', 'opencrq', 'found', crq)];
    testRender(<OpenCrqPivot objectId="vuln-1" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toHaveTextContent('Open in OpenCRQ');
    expect(pivot.closest('a') ?? pivot).toHaveAttribute('href', crq.object_url);
  });

  it('shows a disabled "Not in OpenCRQ" when only OpenAEV holds the object', async () => {
    mocks.results = [result('vuln-1', 'openaev', 'found', aev), result('vuln-1', 'opencrq', 'not_found')];
    testRender(<OpenCrqPivot objectId="vuln-1" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toHaveTextContent('Not in OpenCRQ');
    expect(pivot).toBeDisabled();
  });

  it('shows a disabled muted "OpenCRQ is unavailable" when OpenCRQ could not answer, OpenAEV unaffected', async () => {
    mocks.results = [result('vuln-1', 'openaev', 'found', aev), result('vuln-1', 'opencrq', 'unavailable')];
    testRender(<OpenCrqPivot objectId="vuln-1" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toHaveTextContent('OpenCRQ is unavailable');
    expect(pivot).toHaveAttribute('data-status', 'unavailable');
    expect(pivot).toBeDisabled();
  });

  it('draws nothing for an object type OpenCRQ does not hold (not_supported)', async () => {
    mocks.results = [result('ap-1', 'opencrq', 'not_supported')];
    testRender(<OpenCrqPivot objectId="ap-1" />);
    await waitFor(() => expect(mocks.lookups).toBe(1));
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('opencrq-pivot')).not.toBeInTheDocument();
  });

  it('offers "Connect OpenCRQ" to a user who can configure the platform', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    testRender(<OpenCrqPivot objectId="sys-1" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toHaveTextContent('Connect OpenCRQ');
    expect(pivot.closest('a') ?? pivot).toHaveAttribute('href', XTM_CONNECT_DOC_URL);
    expect(mocks.lookups).toBe(0);
  });

  it('shows a disabled read-only hint to a user who cannot configure the platform', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    mocks.granted = false;
    testRender(<OpenCrqPivot objectId="sys-1" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toBeDisabled();
    expect(pivot).toHaveAttribute('aria-label', 'OpenCRQ is not connected');
  });

  it('shows the risk the counterpart drives in the card, with no link of its own', async () => {
    mocks.results = [result('vuln-1', 'opencrq', 'found', {
      ...crq,
      facts: [
        { key: 'risk_scenarios', value: '3' },
        { key: 'annual_loss', value: '125000' },
        { key: 'fix_value', value: 'not a number' },
        { key: 'unknown', value: '1' },
      ],
    })];
    testRender(<OpenCrqCard objectId="vuln-1" />);
    expect(await screen.findByText('In OpenCRQ')).toBeInTheDocument();
    expect(screen.getByText('Shared identifier: CVE-2024-3400')).toBeInTheDocument();
    const facts = screen.getByTestId('opencrq-card-facts');
    expect(facts).toHaveTextContent('3 risk scenarios');
    expect(facts).toHaveTextContent('Annual loss expectancy:');
    expect(facts).not.toHaveTextContent('Loss avoided by fixing');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('a user without rights in OpenCRQ sees the counterpart without the financial facts', async () => {
    mocks.results = [result('vuln-1', 'opencrq', 'found', crq)];
    testRender(<OpenCrqCard objectId="vuln-1" />);
    expect(await screen.findByText(crq.object_name)).toBeInTheDocument();
    expect(screen.queryByTestId('opencrq-card-facts')).not.toBeInTheDocument();
  });

  it('draws no card when OpenCRQ is not connected or on a lookup error', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    const { unmount } = testRender(<OpenCrqCard objectId="intrusion-1" />);
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('opencrq-card')).not.toBeInTheDocument();
    unmount();
    resetXtmCounterpartCache();
    mocks.connected = { openaev: true, opencrq: true };
    mocks.fail = true;
    testRender(<OpenCrqCard objectId="sys-1" />);
    await new Promise((resolve) => {
      setTimeout(resolve, 80);
    });
    expect(screen.queryByTestId('opencrq-card')).not.toBeInTheDocument();
    expect(screen.queryByText('Not in OpenCRQ')).not.toBeInTheDocument();
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

describe('formatOpenCrqFacts', () => {
  const t = (message: string, options?: { values: Record<string, number> }) => (options ? `${options.values.count} ${message}` : message);
  it('keeps the known numeric facts in display order', () => {
    expect(formatOpenCrqFacts([
      { key: 'fix_value', value: '10' },
      { key: 'risk_scenarios', value: '1' },
    ], t, (v) => `${v}`)).toEqual([
      '1 {count, plural, one {# risk scenario} other {# risk scenarios}}',
      'Loss avoided by fixing: 10',
    ]);
  });
});
