import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import IngestionCatalogUnverifiedDeploymentPopover from './IngestionCatalogUnverifiedDeploymentPopover';

const ACK_LABEL = 'I acknowledge that this connector is not supported by Filigran and deploy it at my own risk';

const renderPopover = () => {
  const onClose = vi.fn();
  const onDeploy = vi.fn();
  testRender(
    <IngestionCatalogUnverifiedDeploymentPopover isOpen onClose={onClose} onDeploy={onDeploy} />,
  );
  return { onClose, onDeploy };
};

describe('IngestionCatalogUnverifiedDeploymentPopover', () => {
  it('keeps Deploy disabled until the acknowledgement is checked', () => {
    renderPopover();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByRole('checkbox')).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('toggles once when the label is clicked', () => {
    renderPopover();
    fireEvent.click(screen.getByText(ACK_LABEL));
    expect(screen.getByRole('checkbox')).toHaveAttribute('aria-checked', 'true');
    fireEvent.click(screen.getByText(ACK_LABEL));
    expect(screen.getByRole('checkbox')).toHaveAttribute('aria-checked', 'false');
  });

  it('deploys and closes once acknowledged', () => {
    const { onClose, onDeploy } = renderPopover();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(onDeploy).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
