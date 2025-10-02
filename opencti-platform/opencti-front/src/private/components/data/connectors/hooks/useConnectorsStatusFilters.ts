import { useEffect, useMemo, useState } from 'react';
import { ConnectorsStatusFilterState } from '@components/data/connectors/ConnectorsStatusFilters';
import { ConnectorsListQuery } from '@components/data/connectors/__generated__/ConnectorsListQuery.graphql';
import { ConnectorsStateQuery } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';

type Connector =
  NonNullable<ConnectorsListQuery['response']['connectors']>[number]
  & Partial<NonNullable<ConnectorsStateQuery['response']['connectors']>[number]>;

type UseConnectorsStatusFiltersProps = {
  connectors: Connector[]
  searchParams: URLSearchParams;
};

const parseBooleanParam = (value: string | null): boolean | null => {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return null;
};

const useConnectorsStatusFilters = ({ connectors, searchParams }: UseConnectorsStatusFiltersProps) => {
  const [filters, setFilters] = useState<ConnectorsStatusFilterState>({
    search: searchParams.get('search') || '',
    slug: searchParams.get('slug') || '',
    isManaged: parseBooleanParam(searchParams.get('is_managed')),
  });

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    if (filters.slug) params.set('slug', filters.slug);
    if (filters.isManaged !== null) params.set('is_managed', String(filters.isManaged));

    const queryString = params.toString();
    const newUrl = queryString ? `${window.location.pathname}?${queryString}` : window.location.pathname;
    // replace history with the params so on back on browser, reload the page with
    // the last filters set
    window.history.replaceState({}, '', newUrl);
  }, [filters]);

  const matchesFilterCriteria = (connector: Connector): boolean => {
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      const connectorIdentifierMatch = connector.name?.toLowerCase().includes(searchLower);
      const displayNameMatch = connector.title?.toLowerCase().includes(searchLower);
      if (!connectorIdentifierMatch && !displayNameMatch) return false;
    }

    if (filters.slug) {
      const connectorSlug = connector.manager_contract_excerpt?.slug?.toLowerCase();
      const filterSlug = filters.slug.toLowerCase();
      if (connectorSlug !== filterSlug) return false;
    }

    if (filters.isManaged !== null) {
      if (connector.is_managed !== filters.isManaged) return false;
    }

    return true;
  };

  const filteredConnectors = useMemo(() => {
    return connectors.filter(matchesFilterCriteria);
  }, [connectors, filters.search, filters.slug, filters.isManaged]);

  return {
    filteredConnectors,
    filters,
    setFilters,
  };
};

export default useConnectorsStatusFilters;
