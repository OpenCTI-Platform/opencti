import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ForcePasswordChange from '../ForcePasswordChange';
import { handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';

const navigateMock = vi.fn();
const commitFnMock = vi.fn();

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [commitFnMock, false],
}));

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
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

  it('renders force password change form fields', () => {
    testRender(<ForcePasswordChange />);
    expect(screen.getByText('PasswordPolicies')).toBeDefined();
    expect(screen.getByLabelText('New password')).toBeDefined();
    expect(screen.getByLabelText('Confirmation')).toBeDefined();
  });

  it('submits mutation and navigates to dashboard on success', async () => {
    const { user } = testRender(<ForcePasswordChange />);

    await user.type(screen.getByLabelText('New password'), 'NewPassword1!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPassword1!');
    await user.click(screen.getByRole('button', { name: 'Change your password' }));

    expect(commitFnMock).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        input: [{ key: 'password', value: ['NewPassword1!'] }],
      },
    }));

    const config = commitFnMock.mock.calls[0][0];
    config.onCompleted?.();

    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('The password has been updated');
    expect(navigateMock).toHaveBeenCalledWith('/dashboard', { replace: true });
  });

  it('handles mutation errors through handleErrorInForm', async () => {
    const { user } = testRender(<ForcePasswordChange />);

    await user.type(screen.getByLabelText('New password'), 'NewPassword1!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPassword1!');
    await user.click(screen.getByRole('button', { name: 'Change your password' }));

    const config = commitFnMock.mock.calls[0][0];
    const fakeError = { res: { errors: [{ message: 'boom' }] } };
    config.onError?.(fakeError);

    expect(handleErrorInForm).toHaveBeenCalled();
  });
});
