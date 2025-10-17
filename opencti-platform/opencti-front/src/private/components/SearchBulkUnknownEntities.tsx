import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { allEntitiesKeyList } from '@components/common/bulk/utils/querySearchEntityByText';
import { SearchBulkUnknownEntitiesQuery, SearchBulkUnknownEntitiesQuery$variables } from '@components/__generated__/SearchBulkUnknownEntitiesQuery.graphql';
import DataTableWithoutFragment from '../../components/dataGrid/DataTableWithoutFragment';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext } from '../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import Loader from '../../components/Loader';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';

const LOCAL_STORAGE_KEY = 'searchBulk_unknownEntities';

const searchBulkUnknownEntitiesQuery = graphql`
  query SearchBulkUnknownEntitiesQuery(
    $count: Int!
    $cursor: ID
    $types: [String]
    $filters: FilterGroup
    $search: String
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    globalSearch(
      first: $count
      after: $cursor
      types: $types,
      search: $search,
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
    @connection(key: "Pagination_globalSearch") {
      edges {
        node {
          id
          entity_type
          ... on StixObject {
            representative {
              main
            }
          }
          ... on HashedObservable {
            hashes {
              algorithm
              hash
            }
          }
        }
      }
    }
  }
`;

interface SearchBulkUnknownEntitiesContentProps {
  values: string[],
  queryRef: PreloadedQuery<SearchBulkUnknownEntitiesQuery>,
}

const SearchBulkUnknownEntitiesContent = ({ values, queryRef }: SearchBulkUnknownEntitiesContentProps) => {
  const matchStixObjectWithSearchValue = (
    stixObject: {
      representative?: { main: string },
      hashes?: readonly ({ readonly algorithm: string, readonly hash?: string | null } | null | undefined)[] | null,
    },
    value: string,
  ) => {
    const representativeMatch = value.toLowerCase() === getMainRepresentative(stixObject).toLowerCase();
    if (!representativeMatch) {
      // try to find in hashes
      if (stixObject.hashes) {
        const hashMatch = stixObject.hashes.some((h) => h?.hash === value);
        if (hashMatch) return hashMatch;
      }
      // other cases ?
    }
    return representativeMatch;
  };

  const data = usePreloadedQuery(searchBulkUnknownEntitiesQuery, queryRef);
  const nodes = data.globalSearch?.edges.map((n) => n.node) ?? [];
  const unknownValues = values.filter((value) => {
    const resolvedStixCoreObjects = nodes.filter((o) => matchStixObjectWithSearchValue(o, value)) ?? [];
    return resolvedStixCoreObjects.length === 0;
  });
  const unknownEntities = unknownValues.map((value) => ({
    id: value.trim(),
    entity_type: 'Unknown',
    value: value.trim(),
  }));
  const dataColumns = {
    entity_type: {},
    value: {},
  };
  return (
    <DataTableWithoutFragment
      data={unknownEntities}
      globalCount={unknownEntities.length}
      dataColumns={dataColumns}
      storageKey={LOCAL_STORAGE_KEY}
    />
  );
};

interface SearchBulkUnknownEntitiesProps {
  values: string[],
  setNumberOfEntities: (n: number) => void,
}

const SearchBulkUnknownEntities = ({ values, setNumberOfEntities }: SearchBulkUnknownEntitiesProps) => {
  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', undefined);

  const queryFilters = values.length > 0
    ? {
      mode: 'and',
      filters: [
        { key: 'entity_type', values: ['Stix-Core-Object'] },
        { key: allEntitiesKeyList, values },
      ],
      filterGroups: [],
    }
    : contextFilters;

  const initialValues = {
    sortBy: 'value',
    orderAsc: true,
  };
  const { viewStorage, paginationOptions } = usePaginationLocalStorage<SearchBulkUnknownEntitiesQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  setNumberOfEntities(viewStorage.numberOfElements?.number ?? 0);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: queryFilters,
    count: 5000,
  } as SearchBulkUnknownEntitiesQuery$variables;

  const queryRef = useQueryLoading<SearchBulkUnknownEntitiesQuery>(searchBulkUnknownEntitiesQuery, queryPaginationOptions);

  return (
    <>
      {queryRef && <React.Suspense fallback={<Loader />}>
        <SearchBulkUnknownEntitiesContent
          values={values}
          queryRef={queryRef}
        />
      </React.Suspense>}
    </>);
};

export default SearchBulkUnknownEntities;
