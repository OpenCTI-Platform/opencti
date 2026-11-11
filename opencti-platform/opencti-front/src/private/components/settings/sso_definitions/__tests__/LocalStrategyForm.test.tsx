import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import LocalStrategyForm from '../LocalStrategyForm';

const commitFnMock = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [commitFnMock, false],
}));

let passwordHistoryFlag = true;
vi.mock('../../../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => flag === 'PASSWORD_HISTORY' && passwordHistoryFlag }),
}));

const mockUseLazyLoadQuery = vi.fn();
vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useLazyLoadQuery: (...args: unknown[]) => mockUseLazyLoadQuery(...args),
  };
});

const HISTORY_LABEL = 'Number of recent passwords that cannot be reused (0 equals disabled)';

const renderForm = (historyCount: number | null = 3) => {
  mockUseLazyLoadQuery.mockReturnValue({
    settings: {
      id: 'settings-id',
      local_auth: { enabled: true },
      password_policy_min_length: 8,
      password_policy_max_length: 0,
      password_policy_min_symbols: 0,
      password_policy_min_numbers: 0,
      password_policy_min_words: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_uppercase: 0,
      password_policy_validity_days: 0,
      password_policy_history_count: historyCount,
      platform_enterprise_edition: { license_validated: false },
      platform_providers: [],
      headers_auth: { enabled: false },
      platform_https_enabled: false,
      is_authentication_by_env: false,
    },
  });
  return testRender(<LocalStrategyForm onCancel={vi.fn()} />);
};

const historyInput = () => screen.getByRole('spinbutton', { name: HISTORY_LABEL }) as HTMLInputElement;

describe('LocalStrategyForm, password history', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    passwordHistoryFlag = true;
  });

  it('shows the saved count, bounded from 0 to 24', () => {
    renderForm(3);
    expect(historyInput().value).toBe('3');
    expect(historyInput()).toHaveAttribute('min', '0');
    expect(historyInput()).toHaveAttribute('max', '24');
  });

  it('hides the field when the feature flag is off', () => {
    passwordHistoryFlag = false;
    renderForm(0);
    expect(screen.queryByRole('spinbutton', { name: HISTORY_LABEL })).toBeNull();
  });

  it('sends the count with the other policies', async () => {
    const { user } = renderForm(3);
    await user.clear(historyInput());
    await user.type(historyInput(), '5');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    await waitFor(() => expect(commitFnMock).toHaveBeenCalled());
    const { input } = (commitFnMock as Mock).mock.calls[0][0].variables;
    expect(input.password_policy_history_count).toBe(5);
    expect(input.password_policy_min_length).toBe(8);
  });

  it('does not send the count when the feature flag is off', async () => {
    passwordHistoryFlag = false;
    const { user } = renderForm(0);
    const minLength = screen.getByRole('spinbutton', { name: 'Number of chars must be greater or equals to' });
    await user.clear(minLength);
    await user.type(minLength, '10');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    await waitFor(() => expect(commitFnMock).toHaveBeenCalled());
    const { input } = (commitFnMock as Mock).mock.calls[0][0].variables;
    expect(input).not.toHaveProperty('password_policy_history_count');
  });

  it('refuses a count out of range or not an integer', async () => {
    const { user } = renderForm(3);
    for (const value of ['25', '2.5']) {
      await user.clear(historyInput());
      await user.type(historyInput(), value);
      await user.click(screen.getByRole('button', { name: 'Update' }));
      expect(await screen.findByText('Must be an integer between 0 and 24')).toBeDefined();
    }
    expect(commitFnMock).not.toHaveBeenCalled();
  });
});
