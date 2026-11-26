import { describe, it, expect, vi, Mock, beforeEach } from 'vitest';
import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import TokenCreationForm from './TokenCreationForm';
import { MESSAGING$ } from '../../../../relay/environment';
import { TokenCreationFormMutation$data } from './__generated__/TokenCreationFormMutation.graphql';

// Mock the mutation
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

import { commitLocalUpdate, commitMutation as relayCommitMutation } from 'relay-runtime';
import { createMockEnvironment } from 'relay-test-utils';
import { commitMutation } from '../../../../relay/environment';

describe('Component: TokenCreationForm', () => {
  const onSuccess = vi.fn();
  const onClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render form fields', () => {
    testRender(
      <TokenCreationForm
        userId="mock-id"
        onSuccess={onSuccess}
        onClose={onClose}
      />,
    );

    expect(screen.getByLabelText('Name')).toBeInTheDocument();
    expect(screen.getByLabelText('Duration')).toBeInTheDocument();
  });

  it('should submit form and call onSuccess with token', async () => {
    const { user } = testRender(
      <TokenCreationForm
        userId="mock-id"
        onSuccess={onSuccess}
        onClose={onClose}
      />,
    );

    // Fill Form
    await user.type(screen.getByLabelText('Name'), 'My Token');
    // Duration is already set to 'Unlimited' (legacy) by default, but let's change it.
    // SelectField is often tricky to test with userEvent if it uses MUI Select.
    // For now, let's keep default duration.

    // Mock mutation implementation
    const commitMutationMock = commitMutation as Mock;
    commitMutationMock.mockImplementation(({ onCompleted }: { onCompleted: (response: TokenCreationFormMutation$data) => void }) => {
      onCompleted({
        userTokenAdd: {
          plaintext_token: 'valid-token-123',
          token_id: 'id-123',
          expires_at: '2023-01-01T00:00:00.000Z',
          masked_token: '***-123',
        },
      });
      return { dispose: vi.fn() };
    });

    // Click Generate
    await user.click(screen.getByRole('button', { name: 'Generate' }));

    await waitFor(() => {
      expect(commitMutation).toHaveBeenCalled();
    });

    // Verify properties passed to mutation
    expect(commitMutation).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        input: {
          name: 'My Token',
          duration: 'UNLIMITED',
        },
      },
    }));

    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('Token generated successfully');
    expect(onSuccess).toHaveBeenCalledWith('valid-token-123');
  });

  it('should append the new token to the profile MeUser, not to the User sharing its id', async () => {
    const environment = createMockEnvironment();
    commitLocalUpdate(environment, (store) => {
      const tokens = [store.create('token-1', 'ApiToken')];
      // The same user as a MeUser (namespaced key) and as a User (raw id), both with the token
      store.create('MeUser:user-id', 'MeUser').setLinkedRecords(tokens, 'api_tokens');
      store.create('user-id', 'User').setLinkedRecords(tokens, 'api_tokens');
    });
    // Run the real mutation, so its updater runs against the store
    (commitMutation as Mock).mockImplementation(({ mutation, variables, updater }) => relayCommitMutation(environment, { mutation, variables, updater }));
    const { user } = testRender(<TokenCreationForm userId="user-id" onSuccess={onSuccess} onClose={onClose} />);

    await user.type(screen.getByLabelText('Name'), 'My Token');
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    await waitFor(() => expect(commitMutation).toHaveBeenCalled());
    environment.mock.resolveMostRecentOperation({
      data: { userTokenAdd: { plaintext_token: 'valid-token-123', token_id: 'id-123', expires_at: null, masked_token: '***-123' } },
    });

    const tokenIds: Record<string, string[] | undefined> = {};
    commitLocalUpdate(environment, (store) => {
      ['MeUser:user-id', 'user-id'].forEach((dataID) => {
        tokenIds[dataID] = store.get(dataID)?.getLinkedRecords('api_tokens')?.map((token) => token.getDataID());
      });
    });
    expect(tokenIds).toEqual({ 'MeUser:user-id': ['token-1', 'id-123'], 'user-id': ['token-1'] });
  });

  it('should handle mutation error', async () => {
    const commitMutationMock = commitMutation as Mock;
    commitMutationMock.mockImplementation(({ onError }: { onError: (error: Error) => void }) => {
      onError(new Error('Mutation failed'));
      return { dispose: vi.fn() };
    });

    const { user } = testRender(
      <TokenCreationForm
        userId="mock-id"
        onSuccess={onSuccess}
        onClose={onClose}
      />,
    );

    await user.type(screen.getByLabelText('Name'), 'Error Token');
    await user.click(screen.getByRole('button', { name: 'Generate' }));

    await waitFor(() => {
      expect(commitMutation).toHaveBeenCalled();
    });

    expect(MESSAGING$.notifyError).toHaveBeenCalledWith('Mutation failed');
    expect(onSuccess).not.toHaveBeenCalled();
  });
});
