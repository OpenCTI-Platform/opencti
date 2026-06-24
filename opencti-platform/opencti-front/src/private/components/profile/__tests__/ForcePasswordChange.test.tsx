import React from 'react';
import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ForcePasswordChange from '../ForcePasswordChange';
import { commitMutation, handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
    commitMutation: vi.fn(),
    handleErrorInForm: vi.fn(),
    MESSAGING$: {
      notifySuccess: vi.fn(),
      notifyError: vi.fn(),
    },
  };
});

vi.mock('../../common/form/PasswordPolicies', () => ({
  default: () => <div>PasswordPolicies</div>,
}));

describe('ForcePasswordChange', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders force password change informational message', () => {
    testRender(<ForcePasswordChange />);
    expect(screen.getByText('You can now set a new password for your account.')).toBeDefined();
  });

  it('submits mutation and navigates to dashboard on success', async () => {
    const { user } = testRender(<ForcePasswordChange />);

    await user.type(screen.getByLabelText('Current password'), 'CurrentPassword1!');
    await user.type(screen.getByLabelText('New password'), 'NewPassword1!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPassword1!');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    const commitMutationMock = commitMutation as Mock;
    expect(commitMutationMock).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        input: { key: 'password', value: 'NewPassword1!' },
        password: 'CurrentPassword1!',
      },
    }));

    const config = commitMutationMock.mock.calls[0][0];
    config.onCompleted?.();

    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('The password has been updated');
    expect(navigateMock).toHaveBeenCalledWith('/dashboard', { replace: true });
  });

  it('handles mutation errors through handleErrorInForm', async () => {
    const { user } = testRender(<ForcePasswordChange />);

    await user.type(screen.getByLabelText('Current password'), 'CurrentPassword1!');
    await user.type(screen.getByLabelText('New password'), 'NewPassword1!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPassword1!');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    const commitMutationMock = commitMutation as Mock;
    const config = commitMutationMock.mock.calls[0][0];
    const fakeError = { res: { errors: [{ message: 'boom' }] } };
    config.onError?.(fakeError);

    expect(handleErrorInForm).toHaveBeenCalled();
  });
});
