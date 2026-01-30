import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import TokenResultView from './TokenResultView';

describe('Component: TokenResultView', () => {
  // Setup clipboard mock
  Object.assign(navigator, {
    clipboard: {
      writeText: vi.fn(),
    },
  });

  const onClose = vi.fn();
  const token = 'secret-token-123';

  it('should render token and warning message', () => {
    testRender(
      <TokenResultView
        token={token}
        onClose={onClose}
      />,
    );

    expect(screen.getByText('Token generated successfully')).toBeInTheDocument();
    expect(screen.getByText(/Make sure to copy/)).toBeInTheDocument();
    // ItemCopy renders the token
    expect(screen.getByText(token)).toBeInTheDocument();
  });

  it('should focus copy button on mount', async () => {
    testRender(
      <TokenResultView
        token={token}
        onClose={onClose}
      />,
    );

    // Verify focus is on the Copy button (from ItemCopy)
    const copyButton = screen.getByRole('button', { name: 'Copy' });
    expect(copyButton).toBeInTheDocument();
    expect(copyButton).toHaveFocus();

    // Verify Close button exists but is not focused
    const closeButton = screen.getByRole('button', { name: 'Close' });
    expect(closeButton).toBeInTheDocument();
    expect(closeButton).not.toHaveFocus();
  });

  it('should call onClose when close button clicked', async () => {
    const { user } = testRender(
      <TokenResultView
        token={token}
        onClose={onClose}
      />,
    );
    const closeButton = screen.getByRole('button', { name: 'Close' });
    await user.click(closeButton);
    expect(onClose).toHaveBeenCalled();
  });
});
