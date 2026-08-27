import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import useDeployedIntegrationsFilters from './useDeployedIntegrationsFilters';
import { DeployedIntegrationItem } from './useDeployedIntegrations';
import { NO_CONNECTOR_ERROR } from '../../../../utils/connectorErrors';

const makeItem = (overrides: Partial<DeployedIntegrationItem> = {}): DeployedIntegrationItem => ({
  id: 'id',
  kind: 'connector',
  sectionKey: 'EXTERNAL_IMPORT',
  name: 'Item',
  status: 'active',
  statusLabel: 'active',
  messagesCount: 0,
  throughputRate: null,
  lastRunDate: null,
  updatedAt: null,
  isManaged: false,
  errorState: NO_CONNECTOR_ERROR,
  detailUrl: '/x',
  searchText: 'item',
  ...overrides,
});

const render = (items: DeployedIntegrationItem[], search = '') => renderHook(
  () => useDeployedIntegrationsFilters({ items, searchParams: new URLSearchParams(search) }),
);

describe('useDeployedIntegrationsFilters - error status facet', () => {
  it('counts connectors in error under the error facet, on top of their lifecycle status', () => {
    const items = [
      makeItem({ id: 'a', status: 'active', errorState: { inError: true, code: 401, message: null, timestamp: null } }),
      makeItem({ id: 'b', status: 'active', name: 'B', searchText: 'b' }),
    ];
    const { result } = render(items);
    expect(result.current.facets.statusCounts.active).toBe(2);
    expect(result.current.facets.statusCounts.error).toBe(1);
  });

  it('keeps only items in error when the error facet is selected', () => {
    const items = [
      makeItem({ id: 'a', name: 'A', searchText: 'a', errorState: { inError: true, code: 403, message: null, timestamp: null } }),
      makeItem({ id: 'b', name: 'B', searchText: 'b' }),
    ];
    const { result } = render(items, 'status=error');
    expect(result.current.filteredItems.map((i) => i.id)).toEqual(['a']);
  });

  it('combines the error facet with a lifecycle status as an OR', () => {
    const items = [
      makeItem({ id: 'a', status: 'inactive', name: 'A', searchText: 'a', errorState: { inError: true, code: 401, message: null, timestamp: null } }),
      makeItem({ id: 'b', status: 'active', name: 'B', searchText: 'b' }),
      makeItem({ id: 'c', status: 'inactive', name: 'C', searchText: 'c' }),
    ];
    const { result } = render(items, 'status=active,error');
    expect(result.current.filteredItems.map((i) => i.id).sort()).toEqual(['a', 'b']);
  });
});
