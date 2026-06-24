import React from 'react';
import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import UserEditionPassword from '../edition/UserEditionPassword';
import { commitMutation, MESSAGING$ } from '../../../../../relay/environment';

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return new Proxy(actual, {
    get(target, prop) {
      if (prop === 'createFragmentContainer') {
        return (component: React.ComponentType) => component;
      }
      return target[prop as keyof typeof target];
    },
  });
});

vi.mock('../../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../../relay/environment')>();
  return {
    ...actual,
    commitMutation: vi.fn(),
    handleError: vi.fn(),
    MESSAGING$: {
      notifySuccess: vi.fn(),
      notifyError: vi.fn(),
    },
  };
});

vi.mock('../../../common/form/PasswordPolicies', () => ({
  default: () => <div>PasswordPolicies</div>,
}));

describe('UserEditionPassword', () => {
  const baseUser = {
    id: 'user-1',
    external: false,
    account_status: 'Active',
    password_valid_until: null,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders force password change button for internal active users', () => {
    testRender(<UserEditionPassword user={baseUser} />);
    expect(screen.getByRole('button', { name: 'Force password change' })).toBeDefined();
  });

  it('hides force password change button for external users', () => {
    testRender(<UserEditionPassword user={{ ...baseUser, external: true }} />);
    expect(screen.queryByRole('button', { name: 'Force password change' })).toBeNull();
  });

  it('hides force password change button for locked users', () => {
    testRender(<UserEditionPassword user={{ ...baseUser, account_status: 'Locked' }} />);
    expect(screen.queryByRole('button', { name: 'Force password change' })).toBeNull();
  });

  it('commits force password change mutation with password_valid_until', async () => {
    const { user } = testRender(<UserEditionPassword user={baseUser} />);

    await user.click(screen.getByRole('button', { name: 'Force password change' }));

    const commitMutationMock = commitMutation as Mock;
    expect(commitMutationMock).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        id: 'user-1',
        input: {
          key: 'password_valid_until',
          value: [expect.any(String)],
        },
      },
    }));

    const config = commitMutationMock.mock.calls[0][0];
    config.onCompleted?.();
    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('Password change will be required at next login');
  });

  it('submits password update mutation', async () => {
    const { user } = testRender(<UserEditionPassword user={baseUser} />);

    await user.type(screen.getByLabelText('Password'), 'NewPassword123!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPassword123!');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    const commitMutationMock = commitMutation as Mock;
    expect(commitMutationMock).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        id: 'user-1',
        input: {
          key: 'password',
          value: 'NewPassword123!',
        },
      },
    }));
  });

  it('renders formatted expiry date when provided', () => {
    const expiry = '2026-01-02T00:00:00.000Z';
    testRender(<UserEditionPassword user={{ ...baseUser, password_valid_until: expiry }} />);

    const formatted = new Intl.DateTimeFormat('fr-FR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    }).format(new Date(expiry));

    expect(screen.getByText(`Expiry: ${formatted}`)).toBeDefined();
  });

  it('does not render expiry for invalid date', () => {
    testRender(<UserEditionPassword user={{ ...baseUser, password_valid_until: 'not-a-date' }} />);
    expect(screen.queryByText(/^Expiry:/)).toBeNull();
  });
});
