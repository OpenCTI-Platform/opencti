import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import TruncatedRawValue from './TruncatedRawValue';

const LONG_VALUE = 'A description long enough to be cut by the History and Audit columns';

// jsdom has no layout: give every element the widths of a value cut by its column
const mockOverflow = (overflowing: boolean) => {
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(100);
  vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockReturnValue(overflowing ? 300 : 100);
};

describe('TruncatedRawValue (text variant, History and Audit)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('opens a truncated value from the keyboard, named by the value itself', async () => {
    mockOverflow(true);
    const { user } = testRender(<TruncatedRawValue value={LONG_VALUE} variant="text" />);

    const button = await screen.findByRole('button', { name: LONG_VALUE });
    await user.tab();
    expect(button).toHaveFocus();
    await user.keyboard('{Enter}');

    expect(await screen.findByRole('dialog', { name: 'Raw value' })).toBeInTheDocument();
  });

  it('shows a value that fits as plain text, not as a button', () => {
    mockOverflow(false);
    testRender(<TruncatedRawValue value="Short" variant="text" />);

    expect(screen.getByText('Short')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
