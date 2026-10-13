import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { commitMutation } from '../../relay/environment';
import AuthBoundary from './AuthBoundary';

vi.mock('../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../relay/environment')>()),
  commitMutation: vi.fn(),
}));

// Dedicated screens are out of scope, only the displayed type matters
vi.mock('../../public/LoginRoot', () => ({
  default: ({ type }: { type: string }) => <div data-testid="login-root">{type}</div>,
}));
vi.mock('./LtsLicenseRoot', () => ({
  default: () => <div data-testid="lts-license-root" />,
}));

// Shape of the errors thrown by react-relay-network-modern
const graphqlError = (code: string, message = 'Something went wrong') => Object.assign(new Error('Relay request failed'), {
  req: { getID: () => 'RootPrivateQuery' },
  res: { status: 200, errors: [{ message, extensions: { code } }] },
});

const Thrower = ({ error }: { error: unknown }) => {
  throw error;
};

describe('AuthBoundary', () => {
  beforeEach(() => {
    vi.mocked(commitMutation).mockClear();
    // React logs caught render errors in the console
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('displays the high level error and reports an unknown GraphQL error', async () => {
    testRender(<AuthBoundary><Thrower error={graphqlError('UNKNOWN_ERROR')} /></AuthBoundary>);
    expect(await screen.findByText(/An unknown error occurred/)).toBeInTheDocument();
    expect(commitMutation).toHaveBeenCalledOnce();
    expect(vi.mocked(commitMutation).mock.calls[0][0].variables.message)
      .toEqual('[GraphQL] RootPrivateQuery failed: UNKNOWN_ERROR: Something went wrong');
  });

  it('displays the high level error and reports a javascript error', async () => {
    testRender(<AuthBoundary><Thrower error={new TypeError('x is not a function')} /></AuthBoundary>);
    expect(await screen.findByText(/An unknown error occurred/)).toBeInTheDocument();
    expect(commitMutation).toHaveBeenCalledOnce();
    expect(vi.mocked(commitMutation).mock.calls[0][0].variables.message).toEqual('TypeError: x is not a function');
  });

  it.each([
    ['AUTH_REQUIRED', 'LOGIN'],
    ['IP_FORBIDDEN', 'LOGIN'],
    ['OTP_REQUIRED_ACTIVATION', '2FA_ACTIVATION'],
    ['OTP_REQUIRED', '2FA_VALIDATION'],
  ])('displays the login screen without reporting %s', async (code, loginType) => {
    testRender(<AuthBoundary><Thrower error={graphqlError(code)} /></AuthBoundary>);
    expect(await screen.findByTestId('login-root')).toHaveTextContent(loginType);
    expect(commitMutation).not.toHaveBeenCalled();
  });

  it('displays the license activation without reporting LTS_REQUIRED_ACTIVATION', async () => {
    testRender(<AuthBoundary><Thrower error={graphqlError('LTS_REQUIRED_ACTIVATION')} /></AuthBoundary>);
    expect(await screen.findByTestId('lts-license-root')).toBeInTheDocument();
    expect(commitMutation).not.toHaveBeenCalled();
  });
});
