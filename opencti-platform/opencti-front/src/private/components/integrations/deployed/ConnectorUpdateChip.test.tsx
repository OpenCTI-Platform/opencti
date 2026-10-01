import { screen } from '@testing-library/react';
import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import ConnectorUpdateChip from './ConnectorUpdateChip';

describe('ConnectorUpdateChip', () => {
  it('should give the version to install in the tooltip', async () => {
    const { user } = testRender(<ConnectorUpdateChip version="7.260915.0" />);

    await user.hover(screen.getByText('Update available'));
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip).toHaveTextContent('Version 7.260915.0 can be installed');
    expect(tooltip).not.toHaveTextContent('A newer version needs a platform upgrade');
  });

  it('should add the platform upgrade hint when a newer version needs it', async () => {
    const { user } = testRender(<ConnectorUpdateChip version="7.260915.0" incompatibility />);

    expect(screen.queryByText('Incompatible')).not.toBeInTheDocument();
    await user.hover(screen.getByText('Update available'));
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip).toHaveTextContent('Version 7.260915.0 can be installed');
    expect(tooltip).toHaveTextContent('A newer version needs a platform upgrade');
  });

  it('should show the version in the label and only the platform upgrade hint in the tooltip', async () => {
    const { user } = testRender(<ConnectorUpdateChip version="7.260915.0" versionInLabel incompatibility />);

    await user.hover(screen.getByText('Update available: 7.260915.0'));
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip).toHaveTextContent('A newer version needs a platform upgrade');
    expect(tooltip).not.toHaveTextContent('can be installed');
  });

  it('should not show a tooltip when there is nothing to add to the label', async () => {
    const { user } = testRender(
      <>
        <ConnectorUpdateChip version="7.260915.0" versionInLabel />
        <ConnectorUpdateChip />
      </>,
    );

    await user.hover(screen.getByText('Update available: 7.260915.0'));
    await user.hover(screen.getByText('Update available'));
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });
});
