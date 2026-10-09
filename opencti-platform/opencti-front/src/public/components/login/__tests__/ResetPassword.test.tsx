import React, { useEffect } from 'react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router';
import { CookiesProvider } from 'react-cookie';
import { createTheme, ThemeOptions, ThemeProvider } from '@mui/material/styles';
import AppIntlProvider from '../../../../components/AppIntlProvider';
import ThemeDark from '../../../../components/ThemeDark';
import { LoginContextProvider, useLoginContext } from '../loginContext';
import ResetPassword, { ResetPwdStep } from '../ResetPassword';
import AlertChangePwd from '../AlertChangePwd';
import { PasswordPolicies } from '../../../../components/PasswordPoliciesAlert';

const commitFnMock = vi.fn();
vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [commitFnMock, false],
}));

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
    handleErrorInForm: vi.fn(),
  };
});

const REUSED_MESSAGE = 'This password has already been used recently. Please choose a different one.';
const THROTTLED_MESSAGE = 'Too many password change attempts. Please try again in a few minutes.';
const EXPIRED_MESSAGE = 'Password reset code expired or not found. Please request a new one.';

// Opens the new-password step, as a validated code would
const OnNewPasswordStep = () => {
  const { setValue } = useLoginContext();
  useEffect(() => {
    setValue('resetPwdStep', ResetPwdStep.RESET_PASSWORD);
  }, []);
  return null;
};

const renderNewPasswordStep = (policies: PasswordPolicies = {}) => {
  // No delay between keystrokes: typing whole passwords stays well within the test timeout
  const user = userEvent.setup({ delay: null });
  render(
    <BrowserRouter useTransitions={false}>
      <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
        <ThemeProvider theme={createTheme(ThemeDark() as ThemeOptions)}>
          <CookiesProvider>
            <LoginContextProvider>
              <OnNewPasswordStep />
              <AlertChangePwd />
              <ResetPassword policies={policies} />
            </LoginContextProvider>
          </CookiesProvider>
        </ThemeProvider>
      </AppIntlProvider>
    </BrowserRouter>,
  );
  return { user };
};

const submitPassword = async (user: ReturnType<typeof userEvent.setup>, password: string) => {
  await user.type(await screen.findByLabelText('Password'), password);
  await user.type(screen.getByLabelText('Password validation'), password);
  await user.click(screen.getByRole('button', { name: 'Change your password' }));
  // Formik validates before it submits, so the request may come after the click
  await waitFor(() => expect(commitFnMock).toHaveBeenCalled());
  return (commitFnMock as Mock).mock.calls[0][0];
};

const refuse = (config: { onError?: (error: unknown) => void }, code: string, message: string) => act(() => {
  config.onError?.({ res: { errors: [{ message, name: code, extensions: { code } }] } });
});

describe('ResetPassword, new password step', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows the password history rule with the other rules', async () => {
    renderNewPasswordStep({ minLength: 8, historyCount: 5 });
    expect(await screen.findByText('Must be different from your last 5 passwords')).toBeDefined();
  });

  it('stays on the step, clears the fields and says why when the password was used recently', async () => {
    const { handleErrorInForm } = await import('../../../../relay/environment');
    const { user } = renderNewPasswordStep();
    const config = await submitPassword(user, 'Used-before-1!');
    expect(config.variables.input.newPassword).toBe('Used-before-1!');

    refuse(config, 'PASSWORD_REUSED', REUSED_MESSAGE);

    // Once in the alert above the form, once under the password field
    expect(await screen.findAllByText(REUSED_MESSAGE)).toHaveLength(2);
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Password validation') as HTMLInputElement).value).toBe('');
    expect(screen.getByRole('button', { name: 'Change your password' })).toBeDefined();
    expect(handleErrorInForm).not.toHaveBeenCalled();
  });

  it('keeps the typed password and shows the throttle message when too many attempts were made', async () => {
    const { handleErrorInForm } = await import('../../../../relay/environment');
    const { user } = renderNewPasswordStep();
    const config = await submitPassword(user, 'Fresh-password-2!');

    refuse(config, 'PASSWORD_CHANGE_THROTTLED', THROTTLED_MESSAGE);

    expect(await screen.findByText(THROTTLED_MESSAGE)).toBeDefined();
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('Fresh-password-2!');
    expect(handleErrorInForm).toHaveBeenCalled();
  });

  it('keeps the typed password and asks for a new code when the code expired on this step', async () => {
    const { user } = renderNewPasswordStep();
    const config = await submitPassword(user, 'Fresh-password-3!');

    refuse(config, 'PASSWORD_RESET_EXPIRED', EXPIRED_MESSAGE);

    expect(await screen.findByText(EXPIRED_MESSAGE)).toBeDefined();
    expect(screen.queryByText('This new password does not comply with the platform policies.')).toBeNull();
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('Fresh-password-3!');
  });

  it('keeps the generic message for the other refusals', async () => {
    const { user } = renderNewPasswordStep();
    const config = await submitPassword(user, 'short');

    refuse(config, 'FUNCTIONAL_ERROR', 'Password must have at least 8 characters');

    expect(await screen.findByText('This new password does not comply with the platform policies.')).toBeDefined();
  });
});
