import { describe, it, expect, vi, Mock } from 'vitest';
import React from 'react';
import { screen, within, act } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { APIACCESS_USETOKEN } from '../../../../utils/hooks/useGranted';
import { TokenListBase } from './TokenList';
import { TokenList_node$data } from '@components/profile/api_tokens/__generated__/TokenList_node.graphql';
import { commitLocalUpdate, commitMutation as relayCommitMutation } from 'relay-runtime';
import { createMockEnvironment } from 'relay-test-utils';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

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

describe('Component: TokenList', () => {
  const mockNode = {
    id: 'user-id',
    api_tokens: [
      {
        id: 'token-1',
        name: 'Test Token 1',
        created_at: '2023-01-01T10:00:00.000Z',
        expires_at: null,
        masked_token: '***1234',
      },
      {
        id: 'token-2',
        name: 'Expired Token',
        created_at: '2022-01-01T10:00:00.000Z',
        expires_at: '2022-02-01T10:00:00.000Z', // Past date
        masked_token: '***5678',
      },
    ],
  } as unknown as TokenList_node$data;

  const userContext = createMockUserContext({
    me: {
      name: 'admin',
      user_email: 'admin@opencti.io',
      firstname: 'Admin',
      lastname: 'OpenCTI',
      language: 'en-us',
      unit_system: 'auto',
      theme: 'default',
      external: true,
      userSubscriptions: { edges: [] },
      capabilities: [{ name: APIACCESS_USETOKEN }],
    },
  });

  it('should render list of tokens', () => {
    testRender(<TokenListBase node={mockNode} />, { userContext });

    expect(screen.getByText('Test Token 1')).toBeInTheDocument();
    expect(screen.getByText('Unlimited')).toBeInTheDocument();

    expect(screen.getByText('Expired Token')).toBeInTheDocument();
    expect(screen.getByText('Expired')).toBeInTheDocument();
  });

  it('should handle token revocation', async () => {
    const { user } = testRender(<TokenListBase node={mockNode} />, { userContext });
    const commitMutationMock = commitMutation as Mock;

    // Click revoke on first token
    const revokeButtons = screen.getAllByLabelText('revoke');
    await user.click(revokeButtons[0]);

    // Dialog should open
    expect(screen.getByText('Revoke API Token')).toBeInTheDocument();
    expect(screen.getByText(/Do you want to revoke the token/)).toBeInTheDocument();

    // Check for token name specifically within the dialog to avoid ambiguity with the list item
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('Test Token 1')).toBeInTheDocument();

    // Confirm revocation
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));

    expect(commitMutationMock).toHaveBeenCalledWith(expect.objectContaining({
      variables: { id: 'token-1' },
    }));

    // Manually trigger success callback since we mocked commitMutation simplistically
    const config = commitMutationMock.mock.calls[0][0];
    act(() => {
      config.onCompleted();
    });

    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('Token revoked successfully');
  });

  it('should remove only the revoked token from the profile MeUser, not from the User sharing its id', async () => {
    const environment = createMockEnvironment();
    commitLocalUpdate(environment, (store) => {
      const tokens = ['token-1', 'token-2'].map((id) => store.create(id, 'ApiToken'));
      // The same user as a MeUser (namespaced key) and as a User (raw id), both with the tokens
      store.create('MeUser:user-id', 'MeUser').setLinkedRecords(tokens, 'api_tokens');
      store.create('user-id', 'User').setLinkedRecords(tokens, 'api_tokens');
    });
    // Run the real mutation, so its updater runs against the store
    (commitMutation as Mock).mockImplementation(({ mutation, variables, updater, onCompleted }) => relayCommitMutation(environment, { mutation, variables, updater, onCompleted }));
    const { user } = testRender(<TokenListBase node={mockNode} />, { userContext });

    await user.click(screen.getAllByLabelText('revoke')[0]);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke' }));
    act(() => environment.mock.resolveMostRecentOperation({ data: { userTokenRevoke: 'token-1' } }));

    const tokenIds: Record<string, string[] | undefined> = {};
    commitLocalUpdate(environment, (store) => {
      ['MeUser:user-id', 'user-id'].forEach((dataID) => {
        tokenIds[dataID] = store.get(dataID)?.getLinkedRecords('api_tokens')?.map((token) => token.getDataID());
      });
    });
    expect(tokenIds).toEqual({ 'MeUser:user-id': ['token-2'], 'user-id': ['token-1', 'token-2'] });
  });

  it('should render empty state', () => {
    const node = { id: 'user-id', api_tokens: [] } as unknown as TokenList_node$data;
    testRender(<TokenListBase node={node} />, { userContext });
    expect(screen.getByText(/No tokens found/)).toBeInTheDocument();
  });
});
