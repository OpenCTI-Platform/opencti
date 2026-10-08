import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import DeployedIntegrationCard from './DeployedIntegrationCard';
import { DeployedIntegrationItem } from './useDeployedIntegrations';

vi.mock('@components/integrations/deployed/DeployedIntegrationPopover', () => ({
  default: () => <button type="button">Open menu</button>,
}));

const item: DeployedIntegrationItem = {
  id: 'connector-1',
  kind: 'connector',
  sectionKey: 'EXTERNAL_IMPORT',
  name: 'My connector',
  status: 'active',
  statusLabel: 'Active',
  messagesCount: null,
  throughputRate: null,
  lastRunDate: null,
  lastSeenAt: null,
  updatedAt: null,
  updateAvailable: false,
  latestCompatibleVersion: null,
  hasNewerIncompatibleVersion: false,
  isManaged: false,
  detailUrl: '/dashboard/integrations/connectors/connector-1',
  searchText: 'my connector',
};

const renderCard = (overrides: Partial<DeployedIntegrationItem>) => testRender(
  <DeployedIntegrationCard item={{ ...item, ...overrides }} onChange={vi.fn()} />,
  { route: '/dashboard/integrations/deployed' },
);

describe('DeployedIntegrationCard', () => {
  it('shows the last heartbeat of a connector as its last seen date', () => {
    renderCard({ lastSeenAt: '2026-02-01T00:00:00.000Z' });
    expect(screen.getByText('Last seen')).toBeInTheDocument();
    expect(screen.queryByText('Modified')).not.toBeInTheDocument();
  });

  it('shows the modification date of an integration without heartbeat', () => {
    renderCard({ kind: 'csv', sectionKey: 'csv', updatedAt: '2026-02-01T00:00:00.000Z' });
    expect(screen.getByText('Modified')).toBeInTheDocument();
    expect(screen.queryByText('Last seen')).not.toBeInTheDocument();
  });

  it('shows no activity date without heartbeat nor modification date', () => {
    renderCard({ lastSeenAt: null, updatedAt: null });
    expect(screen.queryByText('Last seen')).not.toBeInTheDocument();
    expect(screen.queryByText('Modified')).not.toBeInTheDocument();
  });
});
