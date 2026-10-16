import React from 'react';
import { describe, expect, it } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { HuntConnectorDeploymentNotice, HuntConnectorRequiredPermissions } from './HuntConnectorSetup';

describe('Hunt connector setup', () => {
  it('tells where a hunt connector is deployed which account it needs, and links its setup section', () => {
    testRender(<HuntConnectorDeploymentNotice slug="google-secops-hunt" />);
    expect(screen.getByText('Before you start: the account of the hunt connector')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-connector-deployment-docs')).toHaveAttribute(
      'href',
      'https://docs.opencti.io/latest/usage/hunt-connectors/#google-secops',
    );
  });

  it('opens the required permissions until a connection test passed, and folds them on demand', () => {
    const permissions = [{ name: 'search', purpose: 'Create the search jobs of the hunts.' }];
    testRender(<HuntConnectorRequiredPermissions permissions={permissions} documentationUrl={null} defaultOpen />);
    expect(screen.getByTestId('connector-hunt-permissions')).toHaveAttribute('data-open', 'true');
    expect(screen.getByText('search')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('connector-hunt-permissions-toggle'));
    expect(screen.getByTestId('connector-hunt-permissions')).toHaveAttribute('data-open', 'false');
  });
});
