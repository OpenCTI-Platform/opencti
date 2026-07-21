import { useEffect, useMemo, useRef, useState } from 'react';
import { IngestionConnector } from '@components/integrations/catalog/types';
import { IngestionConnectorsCatalogsQuery } from '@components/integrations/catalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';
import { IngestionConnectorType } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';
import { BuiltInIntegrationDefinition } from '@components/integrations/available/builtInIntegrations';
import { MESSAGING$ } from '../../../../../relay/environment';
import { useFormatter } from '../../../../../components/i18n';

export type CatalogSortMode = 'name' | 'deployed' | 'verified';

// Support origin of the item: verified contracts and built-in methods are
// supported by Filigran, the rest by the community.
export type CatalogStatusFacet = 'filigran' | 'community';

export type CatalogDeploymentFacet = 'connector' | 'built-in';

export const CATALOG_STATUS_FACETS: CatalogStatusFacet[] = ['filigran', 'community'];

export const CATALOG_DEPLOYMENT_FACETS: CatalogDeploymentFacet[] = ['connector', 'built-in'];

// Pseudo section key for the built-in ingestion methods, displayed first.
export const BUILT_IN_SECTION_KEY = 'BUILT_IN';

export interface CatalogFilterState {
  search: string;
  types: string[];
  useCases: string[];
  statuses: CatalogStatusFacet[];
  deployments: CatalogDeploymentFacet[];
}

export interface CatalogConnectorEntry {
  connector: IngestionConnector;
  catalogId: string;
}

// Normalized view model: a catalog item is either a marketplace connector
// contract or a built-in ingestion method shipped with the platform.
export interface CatalogItem {
  key: string;
  title: string;
  searchText: string;
  sectionKey: string;
  deployment: CatalogDeploymentFacet;
  verified: boolean;
  useCases: string[];
  deploymentCount: number;
  connector?: CatalogConnectorEntry;
  builtIn?: BuiltInIntegrationDefinition;
}

export interface CatalogSection {
  key: string;
  items: CatalogItem[];
}

export interface BuiltInCatalogInput {
  definition: BuiltInIntegrationDefinition;
  deploymentCount: number;
}

type UseIngestionCatalogFiltersProps = {
  catalogs: NonNullable<IngestionConnectorsCatalogsQuery['response']['catalogs']>;
  deploymentCounts: Map<string, number>;
  builtIns: BuiltInCatalogInput[];
  searchParams: URLSearchParams;
};

// Fixed display order for connector type sections; unknown types are appended.
const CONNECTOR_TYPE_ORDER: string[] = [
  'EXTERNAL_IMPORT',
  'STREAM',
  'INTERNAL_ENRICHMENT',
  'INTERNAL_ANALYSIS',
  'INTERNAL_IMPORT_FILE',
  'INTERNAL_EXPORT_FILE',
  'INTERNAL_INGESTION',
];

// Deduplicated so hand-crafted URLs with repeated values (type=STREAM,STREAM)
// cannot produce duplicate filter chips or duplicate React keys.
const parseListParam = (value: string | null): string[] => {
  if (!value) return [];
  return [...new Set(value.split(',').map((v) => v.trim()).filter((v) => v.length > 0))];
};

const matchesStatus = (item: CatalogItem, status: CatalogStatusFacet): boolean => {
  if (status === 'filigran') return item.verified;
  return !item.verified;
};

type FacetGroup = 'types' | 'useCases' | 'statuses' | 'deployments';

const matchesFilters = (
  item: CatalogItem,
  filters: CatalogFilterState,
  skip?: FacetGroup,
): boolean => {
  if (filters.search) {
    const query = filters.search.toLowerCase();
    if (!item.searchText.includes(query)) return false;
  }
  if (skip !== 'types' && filters.types.length > 0) {
    // The type facet only applies to connectors: built-in methods have no
    // connector type and are filtered out when a type filter is active.
    if (item.deployment === 'built-in') return false;
    if (!filters.types.includes(item.sectionKey)) return false;
  }
  if (skip !== 'useCases' && filters.useCases.length > 0) {
    const useCaseMatch = item.useCases.some((useCase) => filters.useCases.includes(useCase));
    if (!useCaseMatch) return false;
  }
  if (skip !== 'statuses' && filters.statuses.length > 0) {
    const statusMatch = filters.statuses.some((status) => matchesStatus(item, status));
    if (!statusMatch) return false;
  }
  if (skip !== 'deployments' && filters.deployments.length > 0 && !filters.deployments.includes(item.deployment)) {
    return false;
  }
  return true;
};

const parseFiltersFromParams = (searchParams: URLSearchParams): CatalogFilterState => ({
  search: searchParams.get('search') || '',
  types: parseListParam(searchParams.get('type')),
  useCases: parseListParam(searchParams.get('useCase')),
  statuses: parseListParam(searchParams.get('status'))
    .filter((s): s is CatalogStatusFacet => (CATALOG_STATUS_FACETS as string[]).includes(s)),
  deployments: parseListParam(searchParams.get('deployment'))
    .filter((d): d is CatalogDeploymentFacet => (CATALOG_DEPLOYMENT_FACETS as string[]).includes(d)),
});

const parseSortFromParams = (searchParams: URLSearchParams): CatalogSortMode => {
  return (['name', 'deployed', 'verified'] as const).find((mode) => mode === searchParams.get('sort')) ?? 'name';
};

const useIngestionCatalogFilters = ({
  catalogs,
  deploymentCounts,
  builtIns,
  searchParams,
}: UseIngestionCatalogFiltersProps) => {
  const { t_i18n } = useFormatter();

  const [filters, setFilters] = useState<CatalogFilterState>(() => parseFiltersFromParams(searchParams));
  const [sort, setSort] = useState<CatalogSortMode>(() => parseSortFromParams(searchParams));

  // In-page filter changes are persisted with history.replaceState, which does
  // not go through the router: the router search params only change on real
  // navigations (e.g. the hero stat chips linking to a pre-filtered view), in
  // which case the filter state is re-initialized from the new params.
  const searchParamsKey = searchParams.toString();
  const lastSearchParamsKey = useRef(searchParamsKey);
  useEffect(() => {
    if (lastSearchParamsKey.current === searchParamsKey) return;
    lastSearchParamsKey.current = searchParamsKey;
    setFilters(parseFiltersFromParams(searchParams));
    setSort(parseSortFromParams(searchParams));
  }, [searchParamsKey]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    // Values are sorted so the same logical filter set always produces the
    // same canonical URL regardless of selection order.
    if (filters.types.length > 0) params.set('type', [...filters.types].sort().join(','));
    if (filters.useCases.length > 0) params.set('useCase', [...filters.useCases].sort().join(','));
    if (filters.statuses.length > 0) params.set('status', [...filters.statuses].sort().join(','));
    if (filters.deployments.length > 0) params.set('deployment', [...filters.deployments].sort().join(','));
    if (sort !== 'name') params.set('sort', sort);

    const queryString = params.toString();
    const newUrl = queryString ? `${window.location.pathname}?${queryString}` : window.location.pathname;
    // replace history with the params so on back on browser, reload the page
    // with the last filters set
    window.history.replaceState({}, '', newUrl);
  }, [filters, sort]);

  // Flatten every catalog contract into a single item list, parsing the JSON
  // payload only once, and append the built-in ingestion methods.
  const { items, parseFailures } = useMemo(() => {
    const parsedItems: CatalogItem[] = [];
    let failures = 0;
    for (const builtIn of builtIns) {
      const label = t_i18n(builtIn.definition.label);
      const description = t_i18n(builtIn.definition.description);
      parsedItems.push({
        key: `built-in-${builtIn.definition.kind}`,
        title: label,
        searchText: `${label} ${description}`.toLowerCase(),
        sectionKey: BUILT_IN_SECTION_KEY,
        deployment: 'built-in',
        // Built-in methods ship with the platform: supported by Filigran.
        verified: true,
        useCases: [],
        deploymentCount: builtIn.deploymentCount,
        builtIn: builtIn.definition,
      });
    }
    for (const catalog of catalogs) {
      for (const contract of catalog.contracts) {
        try {
          const connector: IngestionConnector = JSON.parse(contract);
          if (connector.manager_supported) {
            parsedItems.push({
              key: `${catalog.id}-${connector.slug}`,
              title: connector.title,
              searchText: [
                connector.title,
                connector.description,
                connector.short_description,
                ...(connector.use_cases ?? []),
              ].join(' ').toLowerCase(),
              sectionKey: connector.container_type,
              deployment: 'connector',
              verified: connector.verified,
              useCases: connector.use_cases ?? [],
              deploymentCount: deploymentCounts.get(connector.container_image) ?? 0,
              connector: { connector, catalogId: catalog.id },
            });
          }
        } catch (_e) {
          failures += 1;
        }
      }
    }
    return { items: parsedItems, parseFailures: failures };
    // t_i18n is intentionally omitted: useFormatter returns a new function
    // identity on every render and the locale cannot change without a reload.
  }, [catalogs, deploymentCounts, builtIns]);

  // t_i18n is intentionally omitted from the dependencies: useFormatter
  // returns a new function identity on every render, so including it would
  // re-fire the notification on each render while failures are present.
  useEffect(() => {
    if (parseFailures > 0) {
      MESSAGING$.notifyError(t_i18n('Failed to parse a contract'));
    }
  }, [parseFailures]);

  // Facet counts follow standard faceted-search semantics: each facet group is
  // counted against the items filtered by everything except itself.
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      if (item.deployment === 'connector' && matchesFilters(item, filters, 'types')) {
        counts[item.sectionKey] = (counts[item.sectionKey] ?? 0) + 1;
      }
    }
    return counts;
  }, [items, filters]);

  const useCaseCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      if (matchesFilters(item, filters, 'useCases')) {
        for (const useCase of item.useCases) {
          counts[useCase] = (counts[useCase] ?? 0) + 1;
        }
      }
    }
    return counts;
  }, [items, filters]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      if (matchesFilters(item, filters, 'statuses')) {
        for (const status of CATALOG_STATUS_FACETS) {
          if (matchesStatus(item, status)) {
            counts[status] = (counts[status] ?? 0) + 1;
          }
        }
      }
    }
    return counts;
  }, [items, filters]);

  const deploymentCountsByFacet = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const item of items) {
      if (matchesFilters(item, filters, 'deployments')) {
        counts[item.deployment] = (counts[item.deployment] ?? 0) + 1;
      }
    }
    return counts;
  }, [items, filters]);

  // All facet values present in the catalog, in display order.
  const availableTypes = useMemo(() => {
    const present = [...new Set(items.filter((item) => item.deployment === 'connector').map((item) => item.sectionKey))];
    const known = present.filter((type) => CONNECTOR_TYPE_ORDER.includes(type));
    const unknown = present.filter((type) => !CONNECTOR_TYPE_ORDER.includes(type)).sort();
    return [
      ...CONNECTOR_TYPE_ORDER.filter((type) => known.includes(type)),
      ...unknown,
    ] as IngestionConnectorType[];
  }, [items]);

  const availableUseCases = useMemo(() => {
    return [...new Set(items.flatMap((item) => item.useCases))].sort();
  }, [items]);

  const filteredItems = useMemo(
    () => items.filter((item) => matchesFilters(item, filters)),
    [items, filters],
  );

  // Results sectioned by kind (built-in first, then connector types), sorted
  // per the active sort mode.
  const sections: CatalogSection[] = useMemo(() => {
    const sortItems = (list: CatalogItem[]) => [...list].sort((a, b) => {
      if (sort === 'deployed' && a.deploymentCount !== b.deploymentCount) {
        return b.deploymentCount - a.deploymentCount;
      }
      if (sort === 'verified' && a.verified !== b.verified) {
        return a.verified ? -1 : 1;
      }
      return a.title.localeCompare(b.title);
    });
    const sectionKeys = [BUILT_IN_SECTION_KEY, ...availableTypes];
    return sectionKeys
      .map((key) => ({
        key,
        items: sortItems(filteredItems.filter((item) => item.sectionKey === key)),
      }))
      .filter((section) => section.items.length > 0);
  }, [filteredItems, availableTypes, sort]);

  const hasActiveFilters = filters.search !== ''
    || filters.types.length > 0
    || filters.useCases.length > 0
    || filters.statuses.length > 0
    || filters.deployments.length > 0;

  const clearAllFilters = () => {
    setFilters({ search: '', types: [], useCases: [], statuses: [], deployments: [] });
  };

  return {
    items,
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
      useCases: availableUseCases,
      typeCounts,
      useCaseCounts,
      statusCounts,
      deploymentCounts: deploymentCountsByFacet,
    },
  };
};

export default useIngestionCatalogFilters;
