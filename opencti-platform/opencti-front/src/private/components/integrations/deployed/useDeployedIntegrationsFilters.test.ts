import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { DeployedIntegrationItem } from './useDeployedIntegrations';
import useDeployedIntegrationsFilters from './useDeployedIntegrationsFilters';

type HookProps = Parameters<typeof useDeployedIntegrationsFilters>[0];

const makeItem = (overrides: Partial<DeployedIntegrationItem> = {}): DeployedIntegrationItem => ({
  id: 'item-1',
  kind: 'connector',
  sectionKey: 'EXTERNAL_IMPORT',
  name: 'Connector A',
  description: null,
  status: 'active',
  statusLabel: 'active',
  messagesCount: 0,
  throughputRate: null,
  lastRunDate: null,
  updatedAt: '2026-01-01T00:00:00.000Z',
  updateAvailable: false,
  latestCompatibleVersion: null,
  hasNewerIncompatibleVersion: false,
  isManaged: true,
  detailUrl: '/dashboard/integrations/connectors/item-1',
  searchText: 'connector a external_import',
  ...overrides,
});

const renderFilters = ({
  items,
  params = '',
}: {
  items: DeployedIntegrationItem[];
  params?: string;
}) => {
  const props: HookProps = {
    items,
    searchParams: new URLSearchParams(params),
  };
  return renderHook((hookProps: HookProps) => useDeployedIntegrationsFilters(hookProps), { initialProps: props });
};

describe('useDeployedIntegrationsFilters', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/');
  });

  it('filters deployed items by update availability when the checkbox is enabled', () => {
    const items = [
      makeItem({ id: 'update-1', name: 'Update 1', updateAvailable: true, latestCompatibleVersion: '7.1.0' }),
      makeItem({ id: 'update-2', name: 'Update 2', updateAvailable: true, latestCompatibleVersion: '7.2.0', status: 'inactive' }),
      makeItem({ id: 'no-update', name: 'No update', updateAvailable: false }),
    ];
    const { result } = renderFilters({ items });

    act(() => {
      result.current.setFilters((prev) => ({ ...prev, updateAvailable: true }));
    });

    expect(result.current.filteredItems.map((item) => item.id).sort()).toEqual(['update-1', 'update-2']);
    expect(result.current.sections).toHaveLength(1);
    expect(result.current.hasActiveFilters).toBe(true);
  });

  it('keeps the update-available count computed with its own facet skipped', () => {
    const items = [
      makeItem({ id: 'active-update', updateAvailable: true, status: 'active' }),
      makeItem({ id: 'inactive-update', updateAvailable: true, status: 'inactive' }),
      makeItem({ id: 'active-no-update', updateAvailable: false, status: 'active' }),
    ];
    const { result } = renderFilters({ items });

    act(() => {
      result.current.setFilters((prev) => ({ ...prev, statuses: ['active'], updateAvailable: true }));
    });

    expect(result.current.filteredItems.map((item) => item.id)).toEqual(['active-update']);
    expect(result.current.facets.updateAvailableCount).toBe(1);
  });

  it('hydrates and persists the update-available checkbox in the URL', () => {
    const items = [
      makeItem({ id: 'update-1', updateAvailable: true }),
      makeItem({ id: 'no-update', updateAvailable: false }),
    ];
    const { result } = renderFilters({ items, params: 'updateAvailable=true' });

    expect(result.current.filters.updateAvailable).toBe(true);
    expect(result.current.filteredItems.map((item) => item.id)).toEqual(['update-1']);

    act(() => {
      result.current.clearAllFilters();
    });

    expect(result.current.filters.updateAvailable).toBe(false);
    expect(window.location.search).toBe('');
  });
});
