import { useEffect, useMemo, useState } from 'react';
import { ConnectorsStatusFilterState } from '@components/data/connectors/ConnectorsStatusFilters';
import { ConnectorsStatus_data$data } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';

type Connector = NonNullable<ConnectorsStatus_data$data['connectors']>[number];

type UseConnectorsStatusFiltersProps = {
  connectors: readonly Connector[]
  searchParams: URLSearchParams;
};

const useConnectorsStatusFilters = ({ connectors, searchParams }: UseConnectorsStatusFiltersProps) => {
  const [filters, setFilters] = useState<ConnectorsStatusFilterState>({
    search: searchParams.get('search') || '',
    managerContractImage: searchParams.get('manager_contract_image') || '',
  });

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    if (filters.managerContractImage) params.set('manager_contract_image', filters.managerContractImage);

    const queryString = params.toString();
    const newUrl = queryString ? `${window.location.pathname}?${queryString}` : window.location.pathname;
    // replace history with the params so on back on browser, reload the page with
    // the last filters set
    window.history.replaceState({}, '', newUrl);
  }, [filters]);

  const matchesFilterCriteria = (connector: Connector): boolean => {
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      const nameMatch = connector.name?.toLowerCase().includes(searchLower);
      if (!nameMatch) return false;
    }

    if (filters.managerContractImage) {
      if (!connector.manager_contract_image) return false;
      const imageMatch = connector.manager_contract_image.includes(filters.managerContractImage);
      if (!imageMatch) return false;
    }

    return true;
  };

  const filteredConnectors = useMemo(() => {
    return connectors.filter(matchesFilterCriteria);
  }, [connectors, filters.search, filters.managerContractImage]);

  return {
    filteredConnectors,
    filters,
    setFilters,
  };
};

export default useConnectorsStatusFilters;
