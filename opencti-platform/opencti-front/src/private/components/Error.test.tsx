import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { commitMutation } from '../../relay/environment';
import { buildErrorLogMessage, ErrorBoundary, getErrorCodes, reportFrontendError } from './Error';

vi.mock('../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../relay/environment')>()),
  commitMutation: vi.fn(),
}));

// Shape of the errors thrown by react-relay-network-modern
const relayError = (operation: string, res: object) => Object.assign(new Error(`Relay request for \`${operation}\` failed`), {
  req: { getID: () => operation },
  res,
});

const graphqlError = (code: string, message = 'Something went wrong') => relayError('ReportsLinesPaginationQuery', {
  status: 200,
  errors: [{ message, extensions: { code } }],
});

const loggedMessage = () => vi.mocked(commitMutation).mock.calls[0][0].variables.message;

describe('Error boundaries reporting', () => {
  beforeEach(() => {
    vi.mocked(commitMutation).mockClear();
  });

  describe('getErrorCodes', () => {
    it('reads codes of direct and ApplicationError wrapped relay errors', () => {
      expect(getErrorCodes(graphqlError('DATABASE_ERROR'))).toEqual(['DATABASE_ERROR']);
      expect(getErrorCodes({ data: graphqlError('UNKNOWN_ERROR') })).toEqual(['UNKNOWN_ERROR']);
      expect(getErrorCodes(new Error('boom'))).toEqual([]);
    });
  });

  describe('buildErrorLogMessage', () => {
    it('describes the failing operation and its GraphQL errors', () => {
      expect(buildErrorLogMessage(graphqlError('AUTH_FAILURE', 'Bad login or password')))
        .toEqual('[GraphQL] ReportsLinesPaginationQuery failed: AUTH_FAILURE: Bad login or password');
    });

    it('describes the HTTP status of a non GraphQL answer', () => {
      expect(buildErrorLogMessage(relayError('RootPrivateQuery', { status: 502 })))
        .toEqual('[GraphQL] RootPrivateQuery failed with HTTP status 502');
    });

    it('unwraps errors wrapped in an ApplicationError', () => {
      expect(buildErrorLogMessage({ data: graphqlError('DATABASE_ERROR', 'Fail to execute engine pagination') }))
        .toEqual('[GraphQL] ReportsLinesPaginationQuery failed: DATABASE_ERROR: Fail to execute engine pagination');
    });

    it('keeps the plain message of javascript errors', () => {
      expect(buildErrorLogMessage(new TypeError('x is not a function'))).toEqual('TypeError: x is not a function');
    });
  });

  describe('reportFrontendError', () => {
    it('reports GraphQL errors to the backend', () => {
      reportFrontendError(graphqlError('UNKNOWN_ERROR'), 'componentStack');
      expect(commitMutation).toHaveBeenCalledOnce();
      expect(vi.mocked(commitMutation).mock.calls[0][0].variables).toMatchObject({
        message: '[GraphQL] ReportsLinesPaginationQuery failed: UNKNOWN_ERROR: Something went wrong',
        componentStack: 'componentStack',
      });
    });

    it('does not report errors handled by the boundary', () => {
      reportFrontendError(graphqlError('FORBIDDEN_ACCESS'), 'componentStack', ['FORBIDDEN_ACCESS']);
      expect(commitMutation).not.toHaveBeenCalled();
    });
  });

  describe('ErrorBoundary', () => {
    const Thrower = ({ error }: { error: unknown }) => {
      throw error;
    };

    beforeEach(() => {
      // React logs caught render errors in the console
      vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    it('displays the generic error and reports a GraphQL error', async () => {
      testRender(<ErrorBoundary><Thrower error={graphqlError('UNKNOWN_ERROR')} /></ErrorBoundary>);
      expect(await screen.findByRole('alert')).toBeInTheDocument();
      expect(commitMutation).toHaveBeenCalledOnce();
      expect(loggedMessage()).toEqual('[GraphQL] ReportsLinesPaginationQuery failed: UNKNOWN_ERROR: Something went wrong');
    });

    it('displays not found without reporting a forbidden access', async () => {
      testRender(<ErrorBoundary><Thrower error={graphqlError('FORBIDDEN_ACCESS')} /></ErrorBoundary>);
      expect(await screen.findByText('This page is not found on this OpenCTI application.')).toBeInTheDocument();
      expect(commitMutation).not.toHaveBeenCalled();
    });

    it('reports javascript errors', async () => {
      testRender(<ErrorBoundary><Thrower error={new TypeError('x is not a function')} /></ErrorBoundary>);
      expect(await screen.findByRole('alert')).toBeInTheDocument();
      expect(loggedMessage()).toEqual('TypeError: x is not a function');
    });
  });
});
