import { useEffect, useMemo, useState } from 'react';
import { BUILT_IN_INTEGRATION_KINDS, isBuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import { DeployedIntegrationItem } from '@components/integrations/deployed/useDeployedIntegrations';

export type DeployedSortMode = 'name' | 'status' | 'lastRun';

export type DeployedStatusFacet = 'active' | 'inactive';

export type DeployedKindFacet = 'connector' | 'built-in';

export const DEPLOYED_STATUS_FACETS: DeployedStatusFacet[] = ['active', 'inactive'];

export const DEPLOYED_KIND_FACETS: DeployedKindFacet[] = ['connector', 'built-in'];

export interface DeployedFilterState {
  search: string;
  types: string[];
  statuses: DeployedStatusFacet[];
  kinds: DeployedKindFacet[];
}

export interface DeployedSection {
  key: string;
  items: DeployedIntegrationItem[];
}

// Fixed display order: connector types first, then the built-in feed kinds.
const CONNECTOR_TYPE_ORDER: string[] = [
  'EXTERNAL_IMPORT',
  'STREAM',
  'INTERNAL_ENRICHMENT',
  'INTERNAL_IMPORT_FILE',
  'INTERNAL_EXPORT_FILE',
  'INTERNAL_INGESTION',
];

const SECTION_ORDER: string[] = [...CONNECTOR_TYPE_ORDER, ...BUILT_IN_INTEGRATION_KINDS];

const parseListParam = (value: string | null): string[] => {
  if (!value) return [];
  return [...new Set(value.split(',').map((v) => v.trim()).filter((v) => v.length > 0))];
};

const itemKindFacet = (item: DeployedIntegrationItem): DeployedKindFacet => {
  return item.kind === 'connector' ? 'connector' : 'built-in';
};

const itemStatusFacet = (item: DeployedIntegrationItem): DeployedStatusFacet => {
  return item.status === 'active' ? 'active' : 'inactive';
};

type FacetGroup = 'types' | 'statuses' | 'kinds';

const matchesFilters = (
  item: DeployedIntegrationItem,
  filters: DeployedFilterState,
  skip?: FacetGroup,
): boolean => {
  if (filters.search) {
    const query = filters.search.toLowerCase();
    if (!item.searchText.includes(query)) return false;
  }
  if (skip !== 'types' && filters.types.length > 0 && !filters.types.includes(item.sectionKey)) {
    return false;
  }
  if (skip !== 'statuses' && filters.statuses.length > 0 && !filters.statuses.includes(itemStatusFacet(item))) {
    return false;
  }
  if (skip !== 'kinds' && filters.kinds.length > 0 && !filters.kinds.includes(itemKindFacet(item))) {
    return false;
  }
  return true;
};

interface UseDeployedIntegrationsFiltersProps {
  items: DeployedIntegrationItem[];
  searchParams: URLSearchParams;
}

const useDeployedIntegrationsFilters = ({ items, searchParams }: UseDeployedIntegrationsFiltersProps) => {
  // The legacy feed screens redirect to /integrations/deployed?kind=<feed>:
  // the kind is folded into the type facet as an initial selection.
  const legacyKind = searchParams.get('kind');
  const initialTypes = [
    ...parseListParam(searchParams.get('type')),
    ...(legacyKind && isBuiltInIntegrationKind(legacyKind) ? [legacyKind] : []),
  ];

  const [filters, setFilters] = useState<DeployedFilterState>({
    search: searchParams.get('search') || '',
    types: [...new Set(initialTypes)],
    statuses: parseListParam(searchParams.get('status'))
      .filter((s): s is DeployedStatusFacet => (DEPLOYED_STATUS_FACETS as string[]).includes(s)),
    kinds: parseListParam(searchParams.get('deployment'))
      .filter((k): k is DeployedKindFacet => (DEPLOYED_KIND_FACETS as string[]).includes(k)),
  });
  const [sort, setSort] = useState<DeployedSortMode>(
    (['name', 'status', 'lastRun'] as const).find((mode) => mode === searchParams.get('sort')) ?? 'name',
  );

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    if (filters.types.length > 0) params.set('type', [...filters.types].sort().join(','));
    if (filters.statuses.length > 0) params.set('status', [...filters.statuses].sort().join(','));
    if (filters.kinds.length > 0) params.set('deployment', [...filters.kinds].sort().join(','));
    if (sort !== 'name') params.set('sort', sort);

    const queryString = params.toString();
    const newUrl = queryString ? `${window.location.pathname}?${queryString}` : window.location.pathname;
    window.history.replaceState({}, '', newUrl);
  }, [filters, sort]);

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      if (matchesFilters(item, filters, 'types')) {
        counts[item.sectionKey] = (counts[item.sectionKey] ?? 0) + 1;
      }
    }
    return counts;
  }, [items, filters]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      if (matchesFilters(item, filters, 'statuses')) {
        const facet = itemStatusFacet(item);
        counts[facet] = (counts[facet] ?? 0) + 1;
      }
    }
    return counts;
  }, [items, filters]);

  const kindCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      if (matchesFilters(item, filters, 'kinds')) {
        const facet = itemKindFacet(item);
        counts[facet] = (counts[facet] ?? 0) + 1;
      }
    }
    return counts;
  }, [items, filters]);

  const availableTypes = useMemo(() => {
    const present = [...new Set(items.map((item) => item.sectionKey))];
    const known = SECTION_ORDER.filter((key) => present.includes(key));
    const unknown = present.filter((key) => !SECTION_ORDER.includes(key)).sort();
    return [...known, ...unknown];
  }, [items]);

  const filteredItems = useMemo(
    () => items.filter((item) => matchesFilters(item, filters)),
    [items, filters],
  );

  const sections: DeployedSection[] = useMemo(() => {
    const statusRank = (item: DeployedIntegrationItem) => {
      if (item.status === 'active') return 0;
      if (item.status === 'processing') return 1;
      return 2;
    };
    const sortItems = (list: DeployedIntegrationItem[]) => [...list].sort((a, b) => {
      if (sort === 'status' && statusRank(a) !== statusRank(b)) {
        return statusRank(a) - statusRank(b);
      }
      if (sort === 'lastRun') {
        const aDate = a.lastRunDate ?? a.updatedAt ?? '';
        const bDate = b.lastRunDate ?? b.updatedAt ?? '';
        if (aDate !== bDate) return bDate.localeCompare(aDate);
      }
      return a.name.localeCompare(b.name);
    });
    return availableTypes
      .map((key) => ({
        key,
        items: sortItems(filteredItems.filter((item) => item.sectionKey === key)),
      }))
      .filter((section) => section.items.length > 0);
  }, [filteredItems, availableTypes, sort]);

  const hasActiveFilters = filters.search !== ''
    || filters.types.length > 0
    || filters.statuses.length > 0
    || filters.kinds.length > 0;

  const clearAllFilters = () => {
    setFilters({ search: '', types: [], statuses: [], kinds: [] });
  };

  return {
    filteredItems,
    sections,
    filters,
    setFilters,
    sort,
    setSort,
    hasActiveFilters,
    clearAllFilters,
    facets: {
      types: availableTypes,
      typeCounts,
      statusCounts,
      kindCounts,
    },
  };
};

export default useDeployedIntegrationsFilters;
