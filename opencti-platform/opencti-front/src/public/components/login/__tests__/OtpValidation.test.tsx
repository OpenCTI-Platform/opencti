import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createTheme, ThemeOptions, ThemeProvider } from '@mui/material/styles';
import AppIntlProvider from '../../../../components/AppIntlProvider';
import ThemeDark from '../../../../components/ThemeDark';
import { LoginContextProvider } from '../loginContext';
import OtpValidation from '../OtpValidation';
import AlertMfa from '../AlertMfa';

const commitFnMock = vi.fn();
vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [commitFnMock, false],
}));

const WRONG_CODE_MESSAGE = 'The code is not correct.';
const PERMANENT_LOCK_MESSAGE = 'Your account has been locked for security reasons. Please contact your administrator.';

type MutationConfig = { variables: unknown; onError?: (error: unknown) => void; onCompleted?: () => void };

const renderOtpValidation = (variant: 'login' | 'resetPassword') => {
  const user = userEvent.setup({ delay: null });
  render(
    <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
      <ThemeProvider theme={createTheme(ThemeDark() as ThemeOptions)}>
        <LoginContextProvider>
          <AlertMfa forceDisplay />
          <OtpValidation variant={variant} transactionId="transaction-id" onCompleted={() => {}} />
        </LoginContextProvider>
      </ThemeProvider>
    </AppIntlProvider>,
  );
  return { user };
};

// Types a whole code, which sends it, and returns the config of the sent mutation
const sendCode = async (user: ReturnType<typeof userEvent.setup>) => {
  const callsBefore = (commitFnMock as Mock).mock.calls.length;
  await user.click(screen.getAllByRole('textbox')[0]);
  await user.keyboard('123456');
  await waitFor(() => expect(commitFnMock).toHaveBeenCalledTimes(callsBefore + 1));
  return (commitFnMock as Mock).mock.calls[callsBefore][0] as MutationConfig;
};

const refuse = (config: MutationConfig, error: { message: string; extensions: Record<string, unknown> }) => act(() => {
  config.onError?.({ res: { errors: [error] } });
});
const wrongCode = { message: 'Bad login or password', extensions: { code: 'AUTH_FAILURE' } };
const temporaryLock = (minutes: number) => ({
  message: 'Your account has been locked for security reasons. Please try again later.',
  extensions: { code: 'AUTH_FAILURE', data: { lock: 'temporary', remaining_minutes: minutes } },
});
const permanentLock = { message: PERMANENT_LOCK_MESSAGE, extensions: { code: 'AUTH_FAILURE', data: { lock: 'permanent' } } };

describe.each(['login', 'resetPassword'] as const)('OtpValidation, %s', (variant) => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('says the code is not correct when it is refused without a lock', async () => {
    const { user } = renderOtpValidation(variant);
    await refuse(await sendCode(user), wrongCode);
    expect(await screen.findByText(WRONG_CODE_MESSAGE)).toBeInTheDocument();
  });

  it('shows the remaining time of a temporary lock instead of a wrong code', async () => {
    const { user } = renderOtpValidation(variant);
    await refuse(await sendCode(user), temporaryLock(15));
    expect(await screen.findByText('Your account has been locked for security reasons. Please try again in 15 minutes.')).toBeInTheDocument();
    expect(screen.queryByText(WRONG_CODE_MESSAGE)).not.toBeInTheDocument();
  });

  it('shows a long temporary lock in hours', async () => {
    const { user } = renderOtpValidation(variant);
    await refuse(await sendCode(user), temporaryLock(180));
    expect(await screen.findByText('Your account has been locked for security reasons. Please try again in 3 hours.')).toBeInTheDocument();
  });

  it('asks to contact the administrator for a permanent lock', async () => {
    const { user } = renderOtpValidation(variant);
    await refuse(await sendCode(user), permanentLock);
    expect(await screen.findByText(PERMANENT_LOCK_MESSAGE)).toBeInTheDocument();
  });

  it('goes back to the wrong code message once the lock is over', async () => {
    const { user } = renderOtpValidation(variant);
    await refuse(await sendCode(user), temporaryLock(1));
    expect(await screen.findByText('Your account has been locked for security reasons. Please try again in 1 minute.')).toBeInTheDocument();
    await refuse(await sendCode(user), wrongCode);
    expect(await screen.findByText(WRONG_CODE_MESSAGE)).toBeInTheDocument();
  });

  it('sends the code with the transaction of the forgotten password flow only', async () => {
    const { user } = renderOtpValidation(variant);
    const config = await sendCode(user);
    expect(config.variables).toEqual({ input: variant === 'login' ? { code: '123456' } : { code: '123456', transactionId: 'transaction-id' } });
  });
});
