import React from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createTheme, ThemeOptions, ThemeProvider } from '@mui/material/styles';
import AppIntlProvider from '../../../../components/AppIntlProvider';
import ThemeDark from '../../../../components/ThemeDark';
import { LoginContextProvider } from '../loginContext';
import LoginForm from '../LoginForm';

const commitFnMock = vi.fn();
vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [commitFnMock, false],
}));

const PERMANENT_LOCK_MESSAGE = 'Your account has been locked for security reasons. Please contact your administrator.';

type MutationConfig = { variables: unknown; onError?: (error: unknown) => void };

// Fills and submits the form, and returns the config of the sent mutation
const signIn = async () => {
  const user = userEvent.setup({ delay: null });
  render(
    <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
      <ThemeProvider theme={createTheme(ThemeDark() as ThemeOptions)}>
        <LoginContextProvider>
          <LoginForm />
        </LoginContextProvider>
      </ThemeProvider>
    </AppIntlProvider>,
  );
  await user.type(screen.getByLabelText('Login'), 'victim@opencti.io');
  await user.type(screen.getByLabelText('Password'), 'wrong-password');
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
  await waitFor(() => expect(commitFnMock).toHaveBeenCalledTimes(1));
  return (commitFnMock as Mock).mock.calls[0][0] as MutationConfig;
};

const refuse = (config: MutationConfig, error: { message: string; extensions: Record<string, unknown> }) => act(() => {
  config.onError?.({ res: { errors: [error] } });
});
const temporaryLock = (minutes: number) => ({
  message: 'Your account has been locked for security reasons. Please try again later.',
  extensions: { code: 'AUTH_FAILURE', data: { lock: 'temporary', remaining_minutes: minutes } },
});

describe('LoginForm, local authentication lockout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('sends the typed email and password', async () => {
    const config = await signIn();
    expect(config.variables).toEqual({ input: { email: 'victim@opencti.io', password: 'wrong-password' } });
  });

  it('keeps the message of a refused login without a lock', async () => {
    await refuse(await signIn(), { message: 'Bad login or password', extensions: { code: 'AUTH_FAILURE' } });
    expect(await screen.findByText('Bad login or password')).toBeInTheDocument();
  });

  it('shows the remaining minutes of a temporary lock', async () => {
    await refuse(await signIn(), temporaryLock(15));
    expect(await screen.findByText('Your account has been locked for security reasons. Please try again in 15 minutes.')).toBeInTheDocument();
  });

  it('shows a long temporary lock in hours', async () => {
    await refuse(await signIn(), temporaryLock(180));
    expect(await screen.findByText('Your account has been locked for security reasons. Please try again in 3 hours.')).toBeInTheDocument();
  });

  it('asks to contact the administrator for a permanent lock', async () => {
    await refuse(await signIn(), { message: PERMANENT_LOCK_MESSAGE, extensions: { code: 'AUTH_FAILURE', data: { lock: 'permanent' } } });
    expect(await screen.findByText(PERMANENT_LOCK_MESSAGE)).toBeInTheDocument();
  });
});
