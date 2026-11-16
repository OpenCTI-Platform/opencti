import { screen, within } from '@testing-library/react';
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import HubCountBadge, { HubTotalBadge } from './HubCountBadge';

const failing = () => {
  throw new Error('count unavailable');
};
// A count whose query never answers.
const pending = () => {
  throw new Promise(() => {});
};

describe('Hub count badges', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows a positive count and nothing for zero or no count', () => {
    testRender(
      <>
        <span data-testid="four"><HubCountBadge useCount={() => 4} /></span>
        <span data-testid="zero"><HubCountBadge useCount={() => 0} /></span>
        <span data-testid="none"><HubCountBadge useCount={() => null} /></span>
      </>,
    );
    expect(within(screen.getByTestId('four')).getByText('4')).toBeInTheDocument();
    expect(within(screen.getByTestId('four')).getByText('4 pending')).toBeInTheDocument();
    expect(screen.getByTestId('zero').textContent).toEqual('');
    expect(screen.getByTestId('none').textContent).toEqual('');
  });

  it('hides a count that fails or has not answered yet, without breaking what is around it', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    testRender(
      <span data-testid="row">
        Alpha
        <HubCountBadge useCount={failing} />
        <HubCountBadge useCount={pending} />
      </span>,
    );
    expect(screen.getByTestId('row').textContent).toEqual('Alpha');
  });

  it('sums the counts of a hub on its menu item, leaving out those that cannot be read', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const counts = [
      { id: 'alpha', useCount: () => 2 },
      { id: 'beta', useCount: () => 3 },
      { id: 'gamma', useCount: failing },
      { id: 'delta', useCount: pending },
      { id: 'epsilon', useCount: () => null },
    ];
    testRender(<span data-testid="total"><HubTotalBadge counts={counts} /></span>);
    expect(await screen.findByText('5')).toBeInTheDocument();
  });

  it('takes out the count of an entry that is no longer listed', async () => {
    const alpha = { id: 'alpha', useCount: () => 2 };
    const beta = { id: 'beta', useCount: () => 3 };
    const { rerender } = testRender(<span data-testid="total"><HubTotalBadge counts={[alpha, beta]} /></span>);
    expect(await screen.findByText('5')).toBeInTheDocument();
    rerender(<span data-testid="total"><HubTotalBadge counts={[beta]} /></span>);
    expect(await screen.findByText('3')).toBeInTheDocument();
    expect(screen.queryByText('5')).not.toBeInTheDocument();
  });

  it.each([
    ['fails', () => {
      throw new Error('count unavailable');
    }],
    ['suspends', () => {
      throw new Promise(() => {});
    }],
  ])('takes out the count of an entry that %s after it answered', async (_state, broken) => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    let current: () => number = () => 3;
    const alpha = { id: 'alpha', useCount: () => 2 };
    const flaky = { id: 'beta', useCount: () => current() };
    const { rerender } = testRender(<span data-testid="total"><HubTotalBadge counts={[alpha, flaky]} /></span>);
    expect(await screen.findByText('5')).toBeInTheDocument();
    current = broken as () => number;
    rerender(<span data-testid="total"><HubTotalBadge counts={[alpha, { ...flaky }]} /></span>);
    expect(await screen.findByText('2')).toBeInTheDocument();
    expect(screen.queryByText('5')).not.toBeInTheDocument();
  });
});
