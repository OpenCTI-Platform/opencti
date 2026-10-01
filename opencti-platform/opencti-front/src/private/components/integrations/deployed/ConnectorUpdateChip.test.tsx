import { screen } from '@testing-library/react';
import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import ConnectorUpdateChip from './ConnectorUpdateChip';

describe('ConnectorUpdateChip', () => {
  it('should show the update without a version', () => {
    testRender(<ConnectorUpdateChip />);

    expect(screen.getByText('Update available')).toBeInTheDocument();
  });

  it('should show the version to install when given', () => {
    testRender(<ConnectorUpdateChip version="7.260915.0" />);

    expect(screen.getByText('Update available: 7.260915.0')).toBeInTheDocument();
  });

  it('should keep the update label when a newer version needs a platform upgrade', async () => {
    const { user } = testRender(<ConnectorUpdateChip version="7.260915.0" incompatibility />);

    expect(screen.getByText('Update available: 7.260915.0')).toBeInTheDocument();
    expect(screen.queryByText('Incompatible')).not.toBeInTheDocument();

    await user.hover(screen.getByText('Update available: 7.260915.0'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('A newer version needs a platform upgrade');
  });

  it('should not explain anything when no newer version needs a platform upgrade', async () => {
    const { user } = testRender(<ConnectorUpdateChip version="7.260915.0" />);

    await user.hover(screen.getByText('Update available: 7.260915.0'));
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });
});
