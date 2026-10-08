import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import DeployedIntegrationLine from './DeployedIntegrationLine';
import { DeployedIntegrationItem } from './useDeployedIntegrations';

vi.mock('@components/integrations/deployed/DeployedIntegrationPopover', () => ({
  default: () => <button type="button">Open menu</button>,
}));

const item: DeployedIntegrationItem = {
  id: 'feed-1',
  kind: 'csv',
  sectionKey: 'csv',
  name: 'Abuse CSV feed',
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
  detailUrl: '/dashboard/integrations/deployed/csv/feed-1',
  searchText: 'abuse csv feed',
};

describe('DeployedIntegrationLine', () => {
  it('is a real link to the detail, so the browser can open it in a new tab', async () => {
    const { user } = testRender(<DeployedIntegrationLine item={item} onChange={vi.fn()} />, { route: '/dashboard/integrations/deployed' });
    const line = screen.getByTestId('integration-line');
    expect(line.tagName).toBe('A');
    expect(line).toHaveAttribute('href', item.detailUrl);
    await user.click(screen.getByText('Abuse CSV feed'));
    expect(window.location.pathname).toBe(item.detailUrl);
  });

  it('keeps the status cell from following the line link', async () => {
    const { user } = testRender(<DeployedIntegrationLine item={item} onChange={vi.fn()} />, { route: '/dashboard/integrations/deployed' });
    await user.click(screen.getByText('Active'));
    expect(window.location.pathname).toBe('/dashboard/integrations/deployed');
  });

  it('keeps a middle click on the status cell from opening the line link in a new tab', () => {
    testRender(<DeployedIntegrationLine item={item} onChange={vi.fn()} />, { route: '/dashboard/integrations/deployed' });
    const middleClick = new MouseEvent('auxclick', { bubbles: true, cancelable: true, button: 1 });
    expect(fireEvent(screen.getByText('Active'), middleClick)).toBe(false);
  });

  it('shows no health chip when there is no ingestion health', () => {
    testRender(<DeployedIntegrationLine item={item} onChange={vi.fn()} />, { route: '/dashboard/integrations/deployed' });
    expect(screen.queryByTestId('ingestion-health-chip')).toBeNull();
  });

  it('shows the health chip next to the status', () => {
    const withHealth = { ...item, health: { status: 'critical', summary: 'No ping received since 2026-10-07T10:00:00.000Z' } };
    testRender(<DeployedIntegrationLine item={withHealth} onChange={vi.fn()} />, { route: '/dashboard/integrations/deployed' });
    expect(screen.getByTestId('ingestion-health-chip')).toHaveTextContent('Critical');
  });
});
