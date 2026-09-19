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
// - import-a: EXTERNAL_IMPORT, verified, use case "SIEM", category "Threat intelligence", Free
// - import-b: EXTERNAL_IMPORT, community, use case "EDR", category "SecOps", Commercial
// - stream-a: STREAM, verified, use cases "SIEM" + "EDR", both categories, Free
// plus the built-in sync method (verified by definition, no categories, no license).
const facetContracts = [
  makeContract({ title: 'Import A', slug: 'import-a', container_type: 'EXTERNAL_IMPORT', verified: true, use_cases: ['SIEM'], solution_categories: ['Threat intelligence'], license_type: 'Free' }),
  makeContract({ title: 'Import B', slug: 'import-b', container_type: 'EXTERNAL_IMPORT', verified: false, use_cases: ['EDR'], solution_categories: ['SecOps'], license_type: 'Commercial' }),
  makeContract({ title: 'Stream A', slug: 'stream-a', container_type: 'STREAM', verified: true, use_cases: ['SIEM', 'EDR'], solution_categories: ['Threat intelligence', 'SecOps'], license_type: 'Free' }),
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
      expect(result.current.facets.solutionCategoryCounts).toEqual({ 'Threat intelligence': 2, SecOps: 2 });
      // The built-in has no license type and is not counted in any bucket.
      expect(result.current.facets.licenseTypeCounts).toEqual({ Free: 2, Commercial: 1 });
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
      expect(result.current.facets.solutionCategoryCounts).toEqual({ 'Threat intelligence': 2, SecOps: 1 });
      expect(result.current.facets.licenseTypeCounts).toEqual({ Free: 2 });
      expect(result.current.facets.deploymentCounts).toEqual({ connector: 2, 'built-in': 1 });
      // ...but the status group itself is counted with the status filter skipped.
      expect(result.current.facets.statusCounts).toEqual({ filigran: 3, community: 1 });
    });

    it('counts the license and category groups with their own filter skipped', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      act(() => result.current.setFilters((prev) => ({ ...prev, licenseTypes: ['Commercial'] })));
      // The license group itself ignores the active license filter...
      expect(result.current.facets.licenseTypeCounts).toEqual({ Free: 2, Commercial: 1 });
      // ...while the other groups only see the Commercial item (import-b).
      expect(result.current.facets.typeCounts).toEqual({ EXTERNAL_IMPORT: 1 });
      expect(result.current.facets.solutionCategoryCounts).toEqual({ SecOps: 1 });
      act(() => result.current.setFilters((prev) => ({ ...prev, licenseTypes: [], solutionCategories: ['SecOps'] })));
      // Same semantics for the category group (import-b + stream-a match).
      expect(result.current.facets.solutionCategoryCounts).toEqual({ 'Threat intelligence': 2, SecOps: 2 });
      expect(result.current.facets.licenseTypeCounts).toEqual({ Free: 1, Commercial: 1 });
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

  describe('solution category and license type filters', () => {
    it('keeps only the items matching a selected solution category', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      act(() => result.current.setFilters((prev) => ({ ...prev, solutionCategories: ['Threat intelligence'] })));
      expect(result.current.filteredItems.map((item) => item.title).sort()).toEqual(['Import A', 'Stream A']);
    });

    it('filters out items without a license type when a license filter is active', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      act(() => result.current.setFilters((prev) => ({ ...prev, licenseTypes: ['Free'] })));
      // The built-in sync method has no license type: it must not match.
      expect(result.current.filteredItems.some((item) => item.deployment === 'built-in')).toBe(false);
      expect(result.current.filteredItems.map((item) => item.title).sort()).toEqual(['Import A', 'Stream A']);
    });

    it('exposes the available categories and license types sorted', () => {
      const { result } = renderFilters({ contracts: facetContracts, builtIns: [builtInSync] });
      expect(result.current.facets.solutionCategories).toEqual(['SecOps', 'Threat intelligence']);
      expect(result.current.facets.licenseTypes).toEqual(['Commercial', 'Free']);
    });

    it('reports active filters and clears them with clearAllFilters', () => {
      const { result } = renderFilters({ contracts: facetContracts });
      expect(result.current.hasActiveFilters).toBe(false);
      act(() => result.current.setFilters((prev) => ({ ...prev, solutionCategories: ['SecOps'], licenseTypes: ['Free'] })));
      expect(result.current.hasActiveFilters).toBe(true);
      act(() => result.current.clearAllFilters());
      expect(result.current.hasActiveFilters).toBe(false);
      expect(result.current.filters.solutionCategories).toEqual([]);
      expect(result.current.filters.licenseTypes).toEqual([]);
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

    it('parses solutionCategory and licenseType params from the URL', () => {
      const { result } = renderFilters({
        contracts: facetContracts,
        params: 'solutionCategory=SecOps,Threat intelligence&licenseType=Free',
      });
      expect(result.current.filters.solutionCategories).toEqual(['SecOps', 'Threat intelligence']);
      expect(result.current.filters.licenseTypes).toEqual(['Free']);
      // Categories match with OR semantics; Commercial import-b is excluded.
      expect(result.current.filteredItems.map((item) => item.title).sort()).toEqual(['Import A', 'Stream A']);
    });

    it('persists solutionCategory and licenseType in the canonical sorted URL', () => {
      const { result } = renderFilters({ contracts: facetContracts });
      act(() => result.current.setFilters((prev) => ({
        ...prev,
        // Selected in reverse order on purpose: the URL must still be canonical.
        solutionCategories: ['Threat intelligence', 'SecOps'],
        licenseTypes: ['Free'],
      })));
      const params = new URLSearchParams(window.location.search);
      expect(params.get('solutionCategory')).toBe('SecOps,Threat intelligence');
      expect(params.get('licenseType')).toBe('Free');
      // Clearing the filters removes the params from the URL.
      act(() => result.current.clearAllFilters());
      expect(window.location.search).toBe('');
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
