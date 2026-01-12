import { describe, it, expect, vi, Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import UserTokenCreationForm from './UserTokenCreationForm';
import { commitMutation } from '../../../../relay/environment';

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

describe('Component: UserTokenCreationForm', () => {
  const userId = 'target-user-id';
  const onClose = vi.fn();
  const onSuccess = vi.fn();

  it('should submit form with correct mutation', async () => {
    const { user } = testRender(
      <UserTokenCreationForm userId={userId} onClose={onClose} onSuccess={onSuccess} />,
    );

    const nameInput = screen.getByLabelText('Name');
    await user.type(nameInput, 'New Admin Token');

    const submitButton = screen.getByRole('button', { name: 'Generate' });
    await user.click(submitButton);

    const commitMutationMock = commitMutation as Mock;

    await waitFor(() => {
      expect(commitMutationMock).toHaveBeenCalledWith(expect.objectContaining({
        variables: {
          userId: 'target-user-id',
          input: expect.objectContaining({
            name: 'New Admin Token',
            duration: 'UNLIMITED',
          }),
        },
      }));
    });
  });
});
