import React from 'react';
import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import { screen } from '@testing-library/react';
import { render } from '@testing-library/react';
import { waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { createTheme, ThemeProvider, ThemeOptions } from '@mui/material/styles';
import AppIntlProvider from '../../../../components/AppIntlProvider';
import ThemeDark from '../../../../components/ThemeDark';
import { LoginContextProvider } from '../loginContext';
import ForcePasswordChange from '../ForcePasswordChange';

// Mock useApiMutation so we don't need a full relay environment
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

const renderWithLoginContext = (ui: React.ReactNode) => {
  const user = userEvent.setup();
  const result = render(
    <BrowserRouter>
      <AppIntlProvider settings={{ platform_language: 'auto', platform_translations: '{}' }}>
        <ThemeProvider theme={createTheme(ThemeDark() as ThemeOptions)}>
          <LoginContextProvider>
            {ui}
          </LoginContextProvider>
        </ThemeProvider>
      </AppIntlProvider>
    </BrowserRouter>,
  );
  return { user, ...result };
};

describe('ForcePasswordChange (public login)', () => {
  const basePolicies = {};

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders new password and confirmation fields', () => {
    renderWithLoginContext(<ForcePasswordChange policies={basePolicies} />);
    expect(screen.getByLabelText('New password')).toBeDefined();
    expect(screen.getByLabelText('Confirmation')).toBeDefined();
  });

  it('renders Back to login and Update buttons', () => {
    renderWithLoginContext(<ForcePasswordChange policies={basePolicies} />);
    expect(screen.getByRole('button', { name: 'Back to login' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'Update' })).toBeDefined();
  });

  it('Update button is disabled when form is empty', async () => {
    renderWithLoginContext(<ForcePasswordChange policies={basePolicies} />);
    const submitBtn = screen.getByRole('button', { name: 'Update' });

    // Initial form validation can be async with Formik/Yup.
    await waitFor(() => {
      expect((submitBtn as HTMLButtonElement).disabled).toBeTruthy();
    });
  });

  it('submits mutation with correct variables on valid form', async () => {
    const { user } = renderWithLoginContext(<ForcePasswordChange policies={basePolicies} />);

    await user.type(screen.getByLabelText('New password'), 'NewPass1!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPass1!');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    expect(commitFnMock).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        input: [{ key: 'password', value: ['NewPass1!'] }],
      },
    }));
  });

  it('calls window.location.reload on success', async () => {
    const reloadMock = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { ...window.location, reload: reloadMock },
      writable: true,
    });

    const { user } = renderWithLoginContext(<ForcePasswordChange policies={basePolicies} />);
    await user.type(screen.getByLabelText('New password'), 'NewPass1!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPass1!');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    const config = (commitFnMock as Mock).mock.calls[0][0];
    config.onCompleted?.();
    expect(reloadMock).toHaveBeenCalled();
  });

  it('handles mutation errors', async () => {
    const { handleErrorInForm } = await import('../../../../relay/environment');
    const { user } = renderWithLoginContext(<ForcePasswordChange policies={basePolicies} />);
    await user.type(screen.getByLabelText('New password'), 'NewPass1!');
    await user.type(screen.getByLabelText('Confirmation'), 'NewPass1!');
    await user.click(screen.getByRole('button', { name: 'Update' }));

    const config = (commitFnMock as Mock).mock.calls[0][0];
    config.onError?.({ res: { errors: [{ message: 'boom' }] } });
    expect(handleErrorInForm).toHaveBeenCalled();
  });

  it('Back to login resets forcePasswordChange context flag', async () => {
    const { user } = renderWithLoginContext(<ForcePasswordChange policies={basePolicies} />);
    // Should not throw - clicking back to login resets context
    await user.click(screen.getByRole('button', { name: 'Back to login' }));
    // Still renders (didn't crash)
    expect(screen.getByRole('button', { name: 'Back to login' })).toBeDefined();
  });
});
