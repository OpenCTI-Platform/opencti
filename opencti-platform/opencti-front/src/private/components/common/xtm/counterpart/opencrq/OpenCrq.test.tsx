import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../../utils/tests/test-render';
import { formatOpenCrqFacts, isOpenCrqKind, OpenCrqCard, OpenCrqPivot, OpenCrqRowMark } from './OpenCrq';
import { XTM_CONNECT_DOC_URL } from '../core/xtmConnect';
import { resetXtmCounterpartCache } from '../core/useXtmCounterparts';

const mocks = vi.hoisted(() => ({
  connected: { openaev: true, opencrq: true } as Record<string, boolean>,
  counterparts: [] as Array<Record<string, unknown>>,
  fail: false,
  lookups: 0,
  granted: true,
}));

vi.mock('../../../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../../relay/environment')>()),
  // The connections query has no variables; the counterparts query has a kind and keys.
  fetchQuery: (_query: unknown, variables: Record<string, unknown> = {}) => ({
    toPromise: () => {
      if (!('keys' in variables)) {
        return Promise.resolve({
          xtmConnections: Object.entries(mocks.connected).map(([product, connected]) => ({ product, connected, url: null })),
        });
      }
      mocks.lookups += 1;
      if (mocks.fail) return Promise.reject(new Error('unreachable'));
      return Promise.resolve({ xtmCounterparts: mocks.counterparts });
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

describe('OpenCRQ pivots', () => {
  beforeEach(() => {
    resetXtmCounterpartCache();
    mocks.connected = { openaev: true, opencrq: true };
    mocks.counterparts = [];
    mocks.fail = false;
    mocks.lookups = 0;
    mocks.granted = true;
  });

  it('opens the OpenCRQ counterpart when both products hold the same key', async () => {
    mocks.counterparts = [aev, crq];
    testRender(<OpenCrqPivot kind="VULNERABILITY" counterpartKey="cve-2024-3400" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toHaveTextContent('Open in OpenCRQ');
    expect(pivot.closest('a') ?? pivot).toHaveAttribute('href', crq.object_url);
  });

  it('shows a disabled "Not in OpenCRQ" when only OpenAEV holds the key', async () => {
    mocks.counterparts = [aev];
    testRender(<OpenCrqPivot kind="VULNERABILITY" counterpartKey="CVE-2024-3400" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toHaveTextContent('Not in OpenCRQ');
    expect(pivot).toBeDisabled();
  });

  it('offers "Connect OpenCRQ" to a user who can configure the platform', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    testRender(<OpenCrqPivot kind="ASSET" counterpartKey="srv-01" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toHaveTextContent('Connect OpenCRQ');
    expect(pivot.closest('a') ?? pivot).toHaveAttribute('href', XTM_CONNECT_DOC_URL);
    expect(mocks.lookups).toBe(0);
  });

  it('shows a disabled read-only hint to a user who cannot configure the platform', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    mocks.granted = false;
    testRender(<OpenCrqPivot kind="ASSET" counterpartKey="srv-01" />);
    const pivot = await screen.findByTestId('opencrq-pivot');
    expect(pivot).toBeDisabled();
    expect(pivot).toHaveAttribute('aria-label', 'OpenCRQ is not connected');
  });

  it('shows the risk the counterpart drives in the card, with no link of its own', async () => {
    mocks.counterparts = [{
      ...crq,
      facts: [
        { key: 'risk_scenarios', value: '3' },
        { key: 'annual_loss', value: '125000' },
        { key: 'fix_value', value: 'not a number' },
        { key: 'unknown', value: '1' },
      ],
    }];
    testRender(<OpenCrqCard kind="VULNERABILITY" counterpartKey="CVE-2024-3400" />);
    expect(await screen.findByText('In OpenCRQ')).toBeInTheDocument();
    expect(screen.getByText('Shared identifier: CVE-2024-3400')).toBeInTheDocument();
    const facts = screen.getByTestId('opencrq-card-facts');
    expect(facts).toHaveTextContent('3 risk scenarios');
    expect(facts).toHaveTextContent('Annual loss expectancy:');
    expect(facts).not.toHaveTextContent('Loss avoided by fixing');
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('draws no card when OpenCRQ is not connected, and degrades to "Not in OpenCRQ" on a lookup error', async () => {
    mocks.connected = { openaev: true, opencrq: false };
    const { unmount } = testRender(<OpenCrqCard kind="THREAT" counterpartKey="intrusion-set--1" />);
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('opencrq-card')).not.toBeInTheDocument();
    unmount();
    resetXtmCounterpartCache();
    mocks.connected = { openaev: true, opencrq: true };
    mocks.fail = true;
    testRender(<OpenCrqCard kind="ASSET" counterpartKey="srv-01" />);
    expect(await screen.findByText('Not in OpenCRQ')).toBeInTheDocument();
  });

  it('marks a list row on a match only, in one batched lookup shared with OpenAEV', async () => {
    mocks.counterparts = [{ ...crq, key: 'srv-01', object_type: 'Asset' }];
    testRender(
      <>
        <OpenCrqRowMark kind="ASSET" counterpartKey="SRV-01" />
        <OpenCrqRowMark kind="ASSET" counterpartKey="srv-02" />
      </>,
    );
    expect(await screen.findByTestId('opencrq-row-mark')).toHaveAttribute('href', crq.object_url);
    await waitFor(() => expect(screen.getAllByTestId('opencrq-row-mark')).toHaveLength(1));
    expect(mocks.lookups).toBe(1);
  });
});

describe('formatOpenCrqFacts and isOpenCrqKind', () => {
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
  it('limits OpenCRQ to threats, vulnerabilities and assets', () => {
    expect(isOpenCrqKind('THREAT')).toBe(true);
    expect(isOpenCrqKind('ATTACK_PATTERN')).toBe(false);
    expect(isOpenCrqKind('ALERT')).toBe(false);
  });
});
