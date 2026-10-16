import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, fireEvent, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import { MODULES_MODMANAGE } from '../../../utils/hooks/useGranted';
import { HuntConnectorDeploymentNotice, HuntConnectorRequiredPermissions, HuntConnectorTestConnection } from './HuntConnectorSetup';

const asUser = (capabilities: string[]) => ({
  userContext: createMockUserContext({ me: { name: 'admin', user_email: 'admin@opencti.io', capabilities: capabilities.map((name) => ({ name })) } as never }),
});

const check = (status: string, overrides: Record<string, unknown> = {}) => ({
  id: 'check-1',
  status,
  requested_at: '2026-10-05T12:00:00.000Z',
  checked_at: status === 'pending' ? null : '2026-10-05T12:00:30.000Z',
  checks: [],
  ...overrides,
});

describe('Hunt connector setup', () => {
  it('tells where a hunt connector is deployed which account it needs, and links its setup section', () => {
    testRender(<HuntConnectorDeploymentNotice slug="google-secops-hunt" />);
    expect(screen.getByText('Before you start: the account of the hunt connector')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-connector-deployment-notice')).toHaveTextContent(/Test connection on its page checks them/);
    expect(screen.getByTestId('hunt-connector-deployment-docs')).toHaveAttribute(
      'href',
      'https://docs.opencti.io/latest/usage/hunt-connectors/#google-secops',
    );
  });

  it('opens the required permissions on demand, with the setup documentation of the connector', () => {
    const permissions = [{ name: 'search', purpose: 'Create the search jobs of the hunts.' }];
    testRender(<HuntConnectorRequiredPermissions permissions={permissions} documentationUrl="https://docs.example.com/splunk-hunt" defaultOpen />);
    expect(screen.getByTestId('connector-hunt-permissions')).toHaveAttribute('data-open', 'true');
    expect(screen.getByText('search')).toBeInTheDocument();
    expect(screen.getByTestId('connector-hunt-permissions-docs')).toHaveAttribute('href', 'https://docs.example.com/splunk-hunt');
    fireEvent.click(screen.getByTestId('connector-hunt-permissions-toggle'));
    expect(screen.getByTestId('connector-hunt-permissions')).toHaveAttribute('data-open', 'false');
  });
});

describe('Connection test of a hunt connector', () => {
  it('offers the test only to a user who manages connectors, and says who can run it otherwise', () => {
    const { unmount } = testRender(<HuntConnectorTestConnection connectorId="connector-1" active check={null} />, asUser([]));
    expect(screen.queryByTestId('connector-hunt-test-connection')).not.toBeInTheDocument();
    expect(screen.getByText('Not tested yet: a user with the Manage connector state capability can test the connection')).toBeInTheDocument();
    unmount();
    testRender(<HuntConnectorTestConnection connectorId="connector-1" active check={null} />, asUser([MODULES_MODMANAGE]));
    expect(screen.getByTestId('connector-hunt-test-connection')).toBeEnabled();
    expect(screen.getByText('Not tested yet: test the connection to check the account and its permissions')).toBeInTheDocument();
  });

  it('cannot test a connector that is not running', () => {
    testRender(<HuntConnectorTestConnection connectorId="connector-1" active={false} check={null} />, asUser([MODULES_MODMANAGE]));
    expect(screen.getByTestId('connector-hunt-test-connection')).toBeDisabled();
    expect(screen.getByText('The connector is not running: start it, then test the connection')).toBeInTheDocument();
  });

  it('shows one plain-words result per check of a finished test', () => {
    const failed = check('failed', {
      checked_at: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
      checks: [
        { name: 'Authentication', ok: true, message: 'The service account signs in.' },
        { name: 'search', ok: false, message: 'The account cannot create search jobs.' },
      ],
    });
    testRender(<HuntConnectorTestConnection connectorId="connector-1" active check={failed} />, asUser([MODULES_MODMANAGE]));
    expect(screen.getByTestId('connector-hunt-check-status')).toHaveAttribute('data-status', 'failed');
    expect(screen.getByTestId('connector-hunt-check-date')).toHaveTextContent('Connection test failed 2 minutes ago');
    const items = screen.getAllByTestId('connector-hunt-check-item');
    expect(items.map((item) => item.getAttribute('data-ok'))).toEqual(['true', 'false']);
    expect(screen.getByText('The account cannot create search jobs.')).toBeInTheDocument();
    expect(screen.getByTestId('connector-hunt-test-connection')).toBeEnabled();
  });

  it('waits for the answer of the connector, and allows a new test once a pending one is stale', () => {
    const { unmount } = testRender(
      <HuntConnectorTestConnection connectorId="connector-1" active check={check('pending', { requested_at: new Date().toISOString() })} />,
      asUser([MODULES_MODMANAGE]),
    );
    expect(screen.getByText('Testing the connection on the platform')).toBeInTheDocument();
    expect(screen.getByTestId('connector-hunt-test-connection')).toBeDisabled();
    unmount();
    testRender(<HuntConnectorTestConnection connectorId="connector-1" active check={check('pending')} />, asUser([MODULES_MODMANAGE]));
    expect(screen.getByText('No answer from the connector yet: it may run a version without connection tests, update it or read its logs')).toBeInTheDocument();
    expect(screen.getByTestId('connector-hunt-test-connection')).toBeEnabled();
  });

  it('asks the connector for a test and shows it pending until the answer', async () => {
    const { relayEnv } = testRender(<HuntConnectorTestConnection connectorId="connector-1" active check={null} />, asUser([MODULES_MODMANAGE]));
    await act(async () => {
      fireEvent.click(screen.getByTestId('connector-hunt-test-connection'));
    });
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.operation.name).toBe('HuntConnectorSetupTestConnectionMutation');
    expect(operation.request.variables).toEqual({ id: 'connector-1' });
    expect(screen.getByTestId('connector-hunt-check-status')).toHaveAttribute('data-status', 'pending');
    expect(screen.getByTestId('connector-hunt-test-connection')).toBeDisabled();
  });
});
