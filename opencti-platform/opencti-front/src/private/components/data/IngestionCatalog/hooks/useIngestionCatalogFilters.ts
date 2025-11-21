import { useEffect, useState } from 'react';
import { FilterState } from '@components/data/IngestionCatalog/IngestionCatalogFilters';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import { IngestionConnectorsCatalogsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';
import { MESSAGING$ } from '../../../../../relay/environment';
import { useFormatter } from '../../../../../components/i18n';

type UseIngestionCatalogFiltersProps = {
  catalogs: NonNullable<IngestionConnectorsCatalogsQuery['response']['catalogs']>;
  searchParams: URLSearchParams;
};

const useIngestionCatalogFilters = ({ catalogs, searchParams }: UseIngestionCatalogFiltersProps) => {
  const { t_i18n } = useFormatter();

  const [filters, setFilters] = useState<FilterState>({
    search: searchParams.get('search') || '',
    type: searchParams.get('type') || '',
    useCase: searchParams.get('useCase') || '',
  });

  useEffect(() => {
    const params = new URLSearchParams();
    if (filters.search) params.set('search', filters.search);
    if (filters.type) params.set('type', filters.type);
    if (filters.useCase) params.set('useCase', filters.useCase);

    const queryString = params.toString();
    const newUrl = queryString ? `${window.location.pathname}?${queryString}` : window.location.pathname;
    // replace history with the params so on back on browser, reload the page with
    // the last filters set
    window.history.replaceState({}, '', newUrl);
  }, [filters]);

  const matchesFilterCriteria = (contract: IngestionConnector): boolean => {
    if (!contract.manager_supported) return false;

    if (filters.search) {
      const searchMatch = contract.title.toLowerCase().includes(filters.search.toLowerCase())
        || contract.description.toLowerCase().includes(filters.search.toLowerCase());

      if (!searchMatch) return false;
    }

    if (filters.type && contract.container_type !== filters.type) {
      return false;
    }

    if (filters.useCase) {
      const useCaseMatch = contract.use_cases?.includes(filters.useCase);
      if (!useCaseMatch) return false;
    }

    return true;
  };

  const filteredCatalogs = catalogs
    .map((catalog) => {
      const filteredContracts: IngestionConnector[] = [];

      for (const contract of catalog.contracts) {
        try {
          const parsedContract = JSON.parse(contract);
          if (matchesFilterCriteria(parsedContract)) {
            filteredContracts.push(parsedContract);
          }
        } catch (_e) {
          MESSAGING$.notifyError(t_i18n('Failed to parse a contract'));
        }
      }

      return { ...catalog, contracts: filteredContracts };
    })
    .filter((catalog) => catalog.contracts.length > 0); // Only return catalogs with contracts

  return {
    filteredCatalogs,
    filters,
    setFilters,
  };
};

export default useIngestionCatalogFilters;
