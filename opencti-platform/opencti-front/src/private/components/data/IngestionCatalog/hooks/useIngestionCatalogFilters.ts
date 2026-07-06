import { useEffect, useMemo, useState } from 'react';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import { IngestionConnectorsCatalogsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';
import { IngestionConnectorType } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import { MESSAGING$ } from '../../../../../relay/environment';
import { useFormatter } from '../../../../../components/i18n';

export type CatalogSortMode = 'name' | 'deployed' | 'verified';

export type CatalogStatusFacet = 'verified' | 'deployed' | 'playbook';

export const CATALOG_STATUS_FACETS: CatalogStatusFacet[] = ['verified', 'deployed', 'playbook'];

export interface CatalogFilterState {
  search: string;
  types: string[];
  useCases: string[];
  statuses: CatalogStatusFacet[];
}

export interface CatalogContractEntry {
  connector: IngestionConnector;
  catalogId: string;
  deploymentCount: number;
}

export interface CatalogSection {
  type: IngestionConnectorType;
  entries: CatalogContractEntry[];
}

type UseIngestionCatalogFiltersProps = {
  catalogs: NonNullable<IngestionConnectorsCatalogsQuery['response']['catalogs']>;
  deploymentCounts: Map<string, number>;
  searchParams: URLSearchParams;
};

// Fixed display order for connector type sections; unknown types are appended.
const CONNECTOR_TYPE_ORDER: string[] = [
  'EXTERNAL_IMPORT',
  'STREAM',
  'INTERNAL_ENRICHMENT',
  'INTERNAL_IMPORT_FILE',
  'INTERNAL_EXPORT_FILE',
  'INTERNAL_INGESTION',
];

const parseListParam = (value: string | null): string[] => {
  if (!value) return [];
  return value.split(',').map((v) => v.trim()).filter((v) => v.length > 0);
};

const matchesStatus = (entry: CatalogContractEntry, status: CatalogStatusFacet): boolean => {
  if (status === 'verified') return entry.connector.verified;
  if (status === 'deployed') return entry.deploymentCount > 0;
  return entry.connector.playbook_supported;
};

const matchesFilters = (
  entry: CatalogContractEntry,
  filters: CatalogFilterState,
  skip?: 'types' | 'useCases' | 'statuses',
): boolean => {
  const { connector } = entry;
  if (filters.search) {
    const query = filters.search.toLowerCase();
    const searchMatch = connector.title.toLowerCase().includes(query)
      || connector.description.toLowerCase().includes(query)
      || connector.short_description.toLowerCase().includes(query)
      || (connector.use_cases ?? []).some((useCase) => useCase.toLowerCase().includes(query));
    if (!searchMatch) return false;
  }
  if (skip !== 'types' && filters.types.length > 0 && !filters.types.includes(connector.container_type)) {
    return false;
  }
  if (skip !== 'useCases' && filters.useCases.length > 0) {
    const useCaseMatch = (connector.use_cases ?? []).some((useCase) => filters.useCases.includes(useCase));
    if (!useCaseMatch) return false;
  }
  if (skip !== 'statuses' && filters.statuses.length > 0) {
    const statusMatch = filters.statuses.some((status) => matchesStatus(entry, status));
    if (!statusMatch) return false;
  }
  return true;
};

const useIngestionCatalogFilters = ({
  catalogs,
  deploymentCounts,
  searchParams,
}: UseIngestionCatalogFiltersProps) => {
  const { t_i18n } = useFormatter();

  const [filters, setFilters] = useState<CatalogFilterState>({
    search: searchParams.get('search') || '',
    types: parseListParam(searchParams.get('type')),
    useCases: parseListParam(searchParams.get('useCase')),
    statuses: parseListParam(searchParams.get('status'))
      .filter((s): s is CatalogStatusFacet => (CATALOG_STATUS_FACETS as string[]).includes(s)),
  });
  const [sort, setSort] = useState<CatalogSortMode>(
    (['name', 'deployed', 'verified'] as const).find((mode) => mode === searchParams.get('sort')) ?? 'name',
  );

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    if (filters.types.length > 0) params.set('type', filters.types.join(','));
    if (filters.useCases.length > 0) params.set('useCase', filters.useCases.join(','));
    if (filters.statuses.length > 0) params.set('status', filters.statuses.join(','));
    if (sort !== 'name') params.set('sort', sort);

    const queryString = params.toString();
    const newUrl = queryString ? `${window.location.pathname}?${queryString}` : window.location.pathname;
    // replace history with the params so on back on browser, reload the page
    // with the last filters set
    window.history.replaceState({}, '', newUrl);
  }, [filters, sort]);

  // Flatten every catalog contract into a single entry list, parsing the JSON
  // payload only once.
  const { entries, parseFailures } = useMemo(() => {
    const parsedEntries: CatalogContractEntry[] = [];
    let failures = 0;
    for (const catalog of catalogs) {
      for (const contract of catalog.contracts) {
        try {
          const connector: IngestionConnector = JSON.parse(contract);
          if (connector.manager_supported) {
            parsedEntries.push({
              connector,
              catalogId: catalog.id,
              deploymentCount: deploymentCounts.get(connector.container_image) ?? 0,
            });
          }
        } catch (_e) {
          failures += 1;
        }
      }
    }
    return { entries: parsedEntries, parseFailures: failures };
  }, [catalogs, deploymentCounts]);

  // t_i18n is intentionally omitted from the dependencies: useFormatter
  // returns a new function identity on every render, so including it would
  // re-fire the notification on each render while failures are present.
  useEffect(() => {
    if (parseFailures > 0) {
      MESSAGING$.notifyError(t_i18n('Failed to parse a contract'));
    }
  }, [parseFailures]);

  // Facet counts follow standard faceted-search semantics: each facet group is
  // counted against the entries filtered by everything except itself.
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const entry of entries) {
      if (matchesFilters(entry, filters, 'types')) {
        counts[entry.connector.container_type] = (counts[entry.connector.container_type] ?? 0) + 1;
      }
    }
    return counts;
  }, [entries, filters]);

  const useCaseCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const entry of entries) {
      if (matchesFilters(entry, filters, 'useCases')) {
        for (const useCase of entry.connector.use_cases ?? []) {
          counts[useCase] = (counts[useCase] ?? 0) + 1;
        }
      }
    }
    return counts;
  }, [entries, filters]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const entry of entries) {
      if (matchesFilters(entry, filters, 'statuses')) {
        for (const status of CATALOG_STATUS_FACETS) {
          if (matchesStatus(entry, status)) {
            counts[status] = (counts[status] ?? 0) + 1;
          }
        }
      }
    }
    return counts;
  }, [entries, filters]);

  // All facet values present in the catalog, in display order.
  const availableTypes = useMemo(() => {
    const present = [...new Set(entries.map((entry) => entry.connector.container_type as string))];
    const known = present.filter((type) => CONNECTOR_TYPE_ORDER.includes(type));
    const unknown = present.filter((type) => !CONNECTOR_TYPE_ORDER.includes(type)).sort();
    return [
      ...CONNECTOR_TYPE_ORDER.filter((type) => known.includes(type)),
      ...unknown,
    ] as IngestionConnectorType[];
  }, [entries]);

  const availableUseCases = useMemo(() => {
    return [...new Set(entries.flatMap((entry) => entry.connector.use_cases ?? []))].sort();
  }, [entries]);

  const filteredEntries = useMemo(
    () => entries.filter((entry) => matchesFilters(entry, filters)),
    [entries, filters],
  );

  // Results sectioned by connector type, sorted per the active sort mode.
  const sections: CatalogSection[] = useMemo(() => {
    const sortEntries = (list: CatalogContractEntry[]) => [...list].sort((a, b) => {
      if (sort === 'deployed' && a.deploymentCount !== b.deploymentCount) {
        return b.deploymentCount - a.deploymentCount;
      }
      if (sort === 'verified' && a.connector.verified !== b.connector.verified) {
        return a.connector.verified ? -1 : 1;
      }
      return a.connector.title.localeCompare(b.connector.title);
    });
    return availableTypes
      .map((type) => ({
        type,
        entries: sortEntries(filteredEntries.filter((entry) => entry.connector.container_type === type)),
      }))
      .filter((section) => section.entries.length > 0);
  }, [filteredEntries, availableTypes, sort]);

  const hasActiveFilters = filters.search !== ''
    || filters.types.length > 0
    || filters.useCases.length > 0
    || filters.statuses.length > 0;

  const clearAllFilters = () => {
    setFilters({ search: '', types: [], useCases: [], statuses: [] });
  };

  return {
    entries,
    filteredEntries,
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
    },
  };
};

export default useIngestionCatalogFilters;
