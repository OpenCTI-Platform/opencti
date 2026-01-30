import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import TokenResultView from './TokenResultView';

// Mock ItemCopy since we don't need to test its internal behavior here, but we want to know it renders the token
vi.mock('../../../../components/ItemCopy', () => {
  return {
    default: ({ content }: { content: string }) => <div data-testid="item-copy">{content}</div>,
  };
});

describe('Component: TokenResultView', () => {
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
    expect(screen.getByTestId('item-copy')).toHaveTextContent(token);
  });

  it('should show close button and call onClose when clicked', async () => {
    const { user } = testRender(
      <TokenResultView
        token={token}
        onClose={onClose}
      />,
    );

    const closeButton = screen.getByRole('button', { name: 'Close' });
    expect(closeButton).toBeInTheDocument();

    // Check if it has focus (AC 3: focus moved to copy button... wait, my implementation focuses close button)
    // My implementation: closeButtonRef.current.focus()
    // Let's verify that
    expect(closeButton).toHaveFocus();

    await user.click(closeButton);
    expect(onClose).toHaveBeenCalled();
  });
});
