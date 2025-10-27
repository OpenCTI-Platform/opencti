import React, { useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { SearchBulkUnknownEntitiesQuery, SearchBulkUnknownEntitiesQuery$variables } from '@components/__generated__/SearchBulkUnknownEntitiesQuery.graphql';
import DataTableWithoutFragment from '../../components/dataGrid/DataTableWithoutFragment';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext } from '../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import Loader from '../../components/Loader';
import type { DataTableProps } from '../../components/dataGrid/dataTableTypes';

const LOCAL_STORAGE_KEY = 'searchBulk_unknownEntities';

const searchBulkUnknownEntitiesQuery = graphql`
  query SearchBulkUnknownEntitiesQuery(
    $filters: FilterGroup
    $values: [String!]!
    $orderBy: UnknownStixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    unknownStixCoreObjects(
      filters: $filters
      values: $values
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

interface SearchBulkUnknownEntitiesContentProps {
  queryRef: PreloadedQuery<SearchBulkUnknownEntitiesQuery>,
  setNumberOfEntities: (n: number) => void,
  isDisplayed: boolean,
}

const SearchBulkUnknownEntitiesContent = ({ queryRef, setNumberOfEntities, isDisplayed }: SearchBulkUnknownEntitiesContentProps) => {
  const data = usePreloadedQuery(searchBulkUnknownEntitiesQuery, queryRef);
  const unknownValues = data.unknownStixCoreObjects;
  useEffect(() => {
    setNumberOfEntities(unknownValues.length ?? 0);
  }, [unknownValues.length]);

  const unknownEntities = unknownValues.map((value) => ({
    id: value.trim(),
    entity_type: 'Unknown',
    value: value.trim(),
  }));
  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: {
      percentWidth: 15,
      isSortable: true,
    },
    value: {
      percentWidth: 85,
      isSortable: true,
    },
  };
  return (
    <>
      {isDisplayed
        && <DataTableWithoutFragment
          data={unknownEntities}
          globalCount={unknownEntities.length}
          dataColumns={dataColumns}
          storageKey={LOCAL_STORAGE_KEY}
           />}
    </>
  );
};

interface SearchBulkUnknownEntitiesProps {
  values: string[],
  setNumberOfEntities: (n: number) => void,
  isDisplayed: boolean,
}

const SearchBulkUnknownEntities = ({ values, setNumberOfEntities, isDisplayed }: SearchBulkUnknownEntitiesProps) => {
  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', undefined);

  const queryFilters = values.length > 0
    ? {
      mode: 'and',
      filters: [
        { key: 'entity_type', values: ['Stix-Core-Object'] },
        { key: 'bulkSearchKeywords', values },
      ],
      filterGroups: [],
    }
    : contextFilters;

  const initialValues = {
    sortBy: 'value',
    orderAsc: true,
  };
  const { paginationOptions } = usePaginationLocalStorage<SearchBulkUnknownEntitiesQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: queryFilters,
    values,
  } as unknown as SearchBulkUnknownEntitiesQuery$variables;

  const queryRef = useQueryLoading<SearchBulkUnknownEntitiesQuery>(searchBulkUnknownEntitiesQuery, queryPaginationOptions);

  return (
    <>
      {queryRef && <React.Suspense fallback={<Loader />}>
        <SearchBulkUnknownEntitiesContent
          queryRef={queryRef}
          setNumberOfEntities={setNumberOfEntities}
          isDisplayed={isDisplayed}
        />
      </React.Suspense>}
    </>);
};

export default SearchBulkUnknownEntities;
