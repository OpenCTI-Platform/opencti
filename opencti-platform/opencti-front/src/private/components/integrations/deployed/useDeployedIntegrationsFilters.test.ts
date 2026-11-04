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
  messagesCount: 0,
  throughputRate: null,
  lastRunDate: null,
  lastSeenAt: null,
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
  isConnectorUpdateEnabled = true,
  isIngestionHealthEnabled = false,
}: {
  items: DeployedIntegrationItem[];
  params?: string;
  isConnectorUpdateEnabled?: boolean;
  isIngestionHealthEnabled?: boolean;
}) => {
  const props: HookProps = {
    items,
    searchParams: new URLSearchParams(params),
    isConnectorUpdateEnabled,
    isIngestionHealthEnabled,
  };
  return renderHook((hookProps: HookProps) => useDeployedIntegrationsFilters(hookProps), { initialProps: props });
};

describe('useDeployedIntegrationsFilters', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/');
  });

  it('sorts by last activity: last run, then connector last heartbeat, then modification date', () => {
    const items = [
      makeItem({ id: 'never-seen', name: 'A never seen', lastSeenAt: null, updatedAt: null }),
      makeItem({ id: 'seen-earlier', name: 'B seen earlier', lastSeenAt: '2026-02-01T00:00:00.000Z', updatedAt: null }),
      makeItem({ id: 'seen-recently', name: 'C seen recently', lastSeenAt: '2026-03-01T00:00:00.000Z', updatedAt: null }),
      makeItem({ id: 'modified', name: 'D modified', lastSeenAt: null, updatedAt: '2026-02-15T00:00:00.000Z' }),
    ];
    const { result } = renderFilters({ items, params: 'sort=lastRun' });

    expect(result.current.sections[0].items.map((item) => item.id)).toEqual(['seen-recently', 'modified', 'seen-earlier', 'never-seen']);
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

  it('ignores the update-available URL parameter when connector update detection is disabled', () => {
    const items = [makeItem({ id: 'no-update', updateAvailable: false })];
    const { result } = renderFilters({ items, params: 'updateAvailable=true', isConnectorUpdateEnabled: false });

    expect(result.current.filters.updateAvailable).toBe(false);
    expect(result.current.filteredItems.map((item) => item.id)).toEqual(['no-update']);
    expect(window.location.search).toBe('');
  });

  describe('health facet', () => {
    const healthItems = () => [
      makeItem({ id: 'critical', name: 'Critical', healthStatus: 'critical' }),
      makeItem({ id: 'degraded', name: 'Degraded', healthStatus: 'degraded' }),
      makeItem({ id: 'healthy', name: 'Healthy', healthStatus: null }),
    ];

    it('filters deployed items by both health severities', () => {
      const { result } = renderFilters({ items: healthItems(), isIngestionHealthEnabled: true });

      act(() => {
        result.current.setFilters((prev) => ({ ...prev, healthStatuses: ['critical', 'degraded'] }));
      });

      expect(result.current.filteredItems.map((item) => item.id).sort()).toEqual(['critical', 'degraded']);
      expect(result.current.hasActiveFilters).toBe(true);
      expect(new URLSearchParams(window.location.search).get('health')).toBe('critical,degraded');
    });

    it('hydrates the health filter from the URL and clears it', () => {
      const { result } = renderFilters({ items: healthItems(), params: 'health=degraded,critical', isIngestionHealthEnabled: true });

      expect(result.current.filters.healthStatuses).toEqual(['degraded', 'critical']);
      expect(result.current.filteredItems.map((item) => item.id).sort()).toEqual(['critical', 'degraded']);

      act(() => {
        result.current.clearAllFilters();
      });

      expect(result.current.filters.healthStatuses).toEqual([]);
      expect(result.current.filteredItems).toHaveLength(3);
      expect(result.current.hasActiveFilters).toBe(false);
      expect(window.location.search).toBe('');
    });

    it('ignores invalid health values in the URL', () => {
      const { result } = renderFilters({ items: healthItems(), params: 'health=critical,healthy,unknown', isIngestionHealthEnabled: true });

      expect(result.current.filters.healthStatuses).toEqual(['critical']);
      expect(result.current.filteredItems.map((item) => item.id)).toEqual(['critical']);
    });

    it('ignores the health URL parameter when ingestion health is disabled', () => {
      const { result } = renderFilters({ items: healthItems(), params: 'health=critical' });

      expect(result.current.filters.healthStatuses).toEqual([]);
      expect(result.current.filteredItems).toHaveLength(3);
      expect(window.location.search).toBe('');
    });

    it('computes health counts with its own facet skipped while respecting the other filters', () => {
      const items = [
        makeItem({ id: 'active-critical', healthStatus: 'critical', status: 'active' }),
        makeItem({ id: 'active-degraded', healthStatus: 'degraded', status: 'active' }),
        makeItem({ id: 'inactive-critical', healthStatus: 'critical', status: 'inactive' }),
        makeItem({ id: 'active-healthy', healthStatus: null, status: 'active' }),
      ];
      const { result } = renderFilters({ items, isIngestionHealthEnabled: true });

      act(() => {
        result.current.setFilters((prev) => ({ ...prev, statuses: ['active'], healthStatuses: ['critical'] }));
      });

      expect(result.current.filteredItems.map((item) => item.id)).toEqual(['active-critical']);
      expect(result.current.facets.healthCounts).toEqual({ critical: 1, degraded: 1 });
    });
  });
});
