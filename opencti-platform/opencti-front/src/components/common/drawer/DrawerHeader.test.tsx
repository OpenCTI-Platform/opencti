import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import DrawerHeader from './DrawerHeader';

describe('DrawerHeader', () => {
  const title = 'Note The encrypted shares are mounted from FS-FIN-02 only; the backup server was not reached';

  it('cuts a long title with an ellipsis and keeps it whole as its tooltip', () => {
    testRender(<DrawerHeader title={title} onClose={vi.fn()} />);
    const heading = screen.getByText(title);
    expect(heading).toHaveAttribute('id', 'drawer-title');
    expect(heading).toHaveAttribute('title', title);
    expect(heading).toHaveStyle({ overflow: 'hidden', textOverflow: 'ellipsis', minWidth: '0' });
  });

  it('keeps the actions next to a long title', () => {
    testRender(<DrawerHeader title={title} onClose={vi.fn()} endContent={<button type="button">Pin</button>} />);
    const actions = screen.getByRole('button', { name: 'Pin' }).parentElement as HTMLElement;
    expect(actions).toContainElement(screen.getByRole('button', { name: 'Close' }));
    expect(actions).toHaveStyle({ flexShrink: '0' });
  });
});
