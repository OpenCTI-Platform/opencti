import { describe, it, expect, vi, Mock } from 'vitest';
import React from 'react';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import { UserTokenList } from './UserTokenList';
import { UserTokenList_node$data } from './__generated__/UserTokenList_node.graphql';
import { MESSAGING$, commitMutation } from '../../../../relay/environment';

// Mock mutation
vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../../relay/environment');
  return {
    ...actual,
    commitMutation: vi.fn(),
    MESSAGING$: {
      notifySuccess: vi.fn(),
      notifyError: vi.fn(),
    },
  };
});

describe('Component: UserTokenList', () => {
  const mockNode = {
    id: 'target-user-id',
    api_tokens: [
      {
        id: 'token-1',
        name: 'Admin View Token',
        created_at: '2023-01-01T10:00:00.000Z',
        expires_at: null,
      },
    ],
  } as unknown as UserTokenList_node$data;

  it('should render list of tokens', () => {
    testRender(<UserTokenList node={mockNode} />);
    expect(screen.getByText('Admin View Token')).toBeInTheDocument();
    expect(screen.getByText('Unlimited')).toBeInTheDocument();
  });

  it('should handle token revocation via admin mutation', async () => {
    const { user } = testRender(<UserTokenList node={mockNode} />);
    const commitMutationMock = commitMutation as Mock;

    // Click revoke
    const revokeButton = screen.getByLabelText('revoke');
    await user.click(revokeButton);

    // Dialog should open
    expect(screen.getByText('Revoke API Token')).toBeInTheDocument();
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('Admin View Token')).toBeInTheDocument();

    // Confirm
    await user.click(screen.getByText('Revoke'));

    // Check mutation variables
    expect(commitMutationMock).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        userId: 'target-user-id',
        id: 'token-1',
      },
    }));

    // Success callback
    const config = commitMutationMock.mock.calls[0][0];
    config.onCompleted();

    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('Token revoked successfully');
  });

  it('should render empty state', () => {
    const node = { id: 'user-id', api_tokens: [] } as unknown as UserTokenList_node$data;
    testRender(<UserTokenList node={node} />);
    expect(screen.getByText(/No tokens found/)).toBeInTheDocument();
  });

  it('should open creation drawer', async () => {
    const { user } = testRender(<UserTokenList node={mockNode} />);
    const generateButton = screen.getByRole('button', { name: 'generate-token' });

    await user.click(generateButton);

    expect(screen.getByText('Generate a new token')).toBeInTheDocument();
  });
});
