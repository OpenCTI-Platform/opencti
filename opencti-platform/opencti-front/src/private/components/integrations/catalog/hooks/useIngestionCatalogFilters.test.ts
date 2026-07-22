import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { BUILT_IN_INTEGRATIONS } from '@components/integrations/available/builtInIntegrations';
import { IngestionConnector } from '@components/integrations/catalog/types';
import useIngestionCatalogFilters, { BUILT_IN_SECTION_KEY, BuiltInCatalogInput } from './useIngestionCatalogFilters';

const mocks = vi.hoisted(() => ({
  notifyError: vi.fn(),
}));

vi.mock('../../../../../relay/environment', () => ({
  MESSAGING$: { notifyError: mocks.notifyError },
}));

vi.mock('../../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (key: string) => key }),
}));

type HookProps = Parameters<typeof useIngestionCatalogFilters>[0];

const makeContract = (overrides: Partial<IngestionConnector> = {}): string => JSON.stringify({
  title: 'Connector',
  slug: 'connector',
  description: 'A connector',
  short_description: 'short',
  use_cases: [],
  verified: false,
  manager_supported: true,
  container_image: 'image/connector',
  container_type: 'EXTERNAL_IMPORT',
  ...overrides,
});

const makeCatalogs = (contracts: string[]) => [
  { id: 'catalog-1', name: 'Catalog', contracts },
] as unknown as HookProps['catalogs'];

const builtInSync: BuiltInCatalogInput = {
  definition: BUILT_IN_INTEGRATIONS.find((definition) => definition.kind === 'sync')!,
  deploymentCount: 0,
};

const renderFilters = ({
  contracts = [],
  builtIns = [],
  deploymentCounts = new Map<string, number>(),
  params = '',
}: {
  contracts?: string[];
  builtIns?: BuiltInCatalogInput[];
  deploymentCounts?: Map<string, number>;
  params?: string;
} = {}) => {
  const props: HookProps = {
    catalogs: makeCatalogs(contracts),
    deploymentCounts,
    builtIns,
    searchParams: new URLSearchParams(params),
  };
  return renderHook((p: HookProps) => useIngestionCatalogFilters(p), { initialProps: props });
};

// A small catalog exercising every facet group:
// - import-a: EXTERNAL_IMPORT, verified, use case "SIEM"
// - import-b: EXTERNAL_IMPORT, community, use case "EDR"
// - stream-a: STREAM, verified, use cases "SIEM" + "EDR"
// plus the built-in sync method (verified by definition).
const facetContracts = [
  makeContract({ title: 'Import A', slug: 'import-a', container_type: 'EXTERNAL_IMPORT', verified: true, use_cases: ['SIEM'] }),
  makeContract({ title: 'Import B', slug: 'import-b', container_type: 'EXTERNAL_IMPORT', verified: false, use_cases: ['EDR'] }),
  makeContract({ title: 'Stream A', slug: 'stream-a', container_type: 'STREAM', verified: true, use_cases: ['SIEM', 'EDR'] }),
];

describe('useIngestionCatalogFilters', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, '', '/');
  });

  describe('facet counting', () => {
    it('counts every facet group without any active filter', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      expect(result.current.facets.typeCounts).toEqual({ EXTERNAL_IMPORT: 2, STREAM: 1 });
      expect(result.current.facets.useCaseCounts).toEqual({ SIEM: 2, EDR: 2 });
      // 3 verified (2 connectors + built-in), 1 community
      expect(result.current.facets.statusCounts).toEqual({ filigran: 3, community: 1 });
      expect(result.current.facets.deploymentCounts).toEqual({ connector: 3, 'built-in': 1 });
    });

    it('counts each facet group against items filtered by every group except itself', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      act(() => result.current.setFilters((prev) => ({ ...prev, statuses: ['filigran'] })));
      // Type counts honor the status filter (only verified connectors remain)...
      expect(result.current.facets.typeCounts).toEqual({ EXTERNAL_IMPORT: 1, STREAM: 1 });
      expect(result.current.facets.useCaseCounts).toEqual({ SIEM: 2, EDR: 1 });
      expect(result.current.facets.deploymentCounts).toEqual({ connector: 2, 'built-in': 1 });
      // ...but the status group itself is counted with the status filter skipped.
      expect(result.current.facets.statusCounts).toEqual({ filigran: 3, community: 1 });
    });

    it('keeps a facet count accurate when the facet itself is selected', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      const before = result.current.facets.typeCounts;
      act(() => result.current.setFilters((prev) => ({ ...prev, types: ['STREAM'] })));
      // Selecting STREAM must not change the type counts themselves: the other
      // type options keep displaying the count they would produce if selected.
      expect(result.current.facets.typeCounts).toEqual(before);
      // The other groups do honor the active type filter.
      expect(result.current.facets.useCaseCounts).toEqual({ SIEM: 1, EDR: 1 });
      expect(result.current.facets.statusCounts).toEqual({ filigran: 1 });
      expect(result.current.facets.deploymentCounts).toEqual({ connector: 1 });
    });
  });

  describe('type filter and built-in items', () => {
    it('filters out built-in methods when any type filter is active', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      expect(result.current.filteredItems.some((item) => item.deployment === 'built-in')).toBe(true);
      act(() => result.current.setFilters((prev) => ({ ...prev, types: ['EXTERNAL_IMPORT'] })));
      expect(result.current.filteredItems.some((item) => item.deployment === 'built-in')).toBe(false);
      expect(result.current.filteredItems.map((item) => item.title)).toEqual(['Import A', 'Import B']);
      expect(result.current.sections.some((section) => section.key === BUILT_IN_SECTION_KEY)).toBe(false);
    });
  });

  describe('contract parsing', () => {
    it('keeps valid contracts, skips malformed ones and notifies exactly once', () => {
      const { result, rerender } = renderFilters({
        contracts: [
          makeContract({ title: 'Valid A', slug: 'valid-a' }),
          '{ this is not JSON',
          makeContract({ title: 'Valid B', slug: 'valid-b' }),
          'also broken }',
        ],
      });
      // Both valid contracts survive, both malformed ones are skipped.
      expect(result.current.items.map((item) => item.title).sort()).toEqual(['Valid A', 'Valid B']);
      // The toast fires exactly once for the whole batch, not once per item.
      expect(mocks.notifyError).toHaveBeenCalledTimes(1);
      expect(mocks.notifyError).toHaveBeenCalledWith('Failed to parse a contract');
      // Re-rendering with the same inputs must not re-fire the notification.
      rerender({
        catalogs: makeCatalogs([
          makeContract({ title: 'Valid A', slug: 'valid-a' }),
          '{ this is not JSON',
          makeContract({ title: 'Valid B', slug: 'valid-b' }),
          'also broken }',
        ]),
        deploymentCounts: new Map<string, number>(),
        builtIns: [],
        searchParams: new URLSearchParams(),
      });
      expect(mocks.notifyError).toHaveBeenCalledTimes(1);
    });

    it('does not notify when every contract is valid', () => {
      renderFilters({ contracts: [makeContract()] });
      expect(mocks.notifyError).not.toHaveBeenCalled();
    });

    it('skips contracts that are not manager supported', () => {
      const { result } = renderFilters({
        contracts: [makeContract({ title: 'Unsupported', manager_supported: false })],
      });
      expect(result.current.items).toEqual([]);
    });
  });

  describe('URL params parsing', () => {
    it('keeps only valid facet values from the URL', () => {
      const { result } = renderFilters({
        contracts: facetContracts,
        builtIns: [builtInSync],
        params: 'status=filigran,bogus&deployment=connector,nope&useCase=SIEM',
      });
      expect(result.current.filters.statuses).toEqual(['filigran']);
      expect(result.current.filters.deployments).toEqual(['connector']);
      expect(result.current.filters.useCases).toEqual(['SIEM']);
    });

    it('deduplicates and trims repeated values from hand-crafted URLs', () => {
      const { result } = renderFilters({
        contracts: facetContracts,
        params: 'type=STREAM,STREAM, EXTERNAL_IMPORT ,,',
      });
      expect(result.current.filters.types).toEqual(['STREAM', 'EXTERNAL_IMPORT']);
    });

    it('falls back to the name sort when the sort param is unknown', () => {
      const { result } = renderFilters({ contracts: facetContracts, params: 'sort=bogus' });
      expect(result.current.sort).toBe('name');
    });

    it('keeps a valid sort param', () => {
      const { result } = renderFilters({ contracts: facetContracts, params: 'sort=deployed' });
      expect(result.current.sort).toBe('deployed');
    });
  });

  describe('sections', () => {
    it('returns an empty array when there is no catalog data at all', () => {
      const { result } = renderFilters();
      expect(result.current.sections).toEqual([]);
    });

    it('returns an empty array when the active filters empty every section', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      act(() => result.current.setFilters((prev) => ({ ...prev, search: 'no match for sure' })));
      expect(result.current.sections).toEqual([]);
    });

    it('orders sections with built-in first then the known type order', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      expect(result.current.sections.map((section) => section.key)).toEqual([
        BUILT_IN_SECTION_KEY,
        'EXTERNAL_IMPORT',
        'STREAM',
      ]);
    });
  });
});
