import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { SavedFiltersQuery } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import getSavedFilterScopeFilter from './getSavedFilterScopeFilter';
import SavedFilterSelection from './SavedFilterSelection';

const savedFiltersQuery = graphql`
  query SavedFiltersQuery($filters: FilterGroup) {
    savedFilters(first: 100, filters: $filters) @connection(key: "SavedFilters__savedFilters") {
      edges {
        node {
          id
          name
          filters
          scope
        }
      }
    }
  }
`;

type SavedFiltersComponentProps = {
  queryRef: PreloadedQuery<SavedFiltersQuery>;
};

const SavedFiltersComponent = ({ queryRef }: SavedFiltersComponentProps) => {
  const { savedFilters } = usePreloadedQuery(savedFiltersQuery, queryRef);

  return (
    <>
      <SavedFilterSelection
        isDisabled={!savedFilters?.edges.length}
        data={savedFilters?.edges.map(({ node }) => node) ?? []}
      />
    </>
  );
};

const SavedFilters = () => {
  const {
    useDataTablePaginationLocalStorage: {
      localStorageKey,
    },
  } = useDataTableContext();

  const filters = getSavedFilterScopeFilter(localStorageKey);

  const queryRef = useQueryLoading<SavedFiltersQuery>(savedFiltersQuery, { filters });

  return (
    <>
      {queryRef && (
        <SavedFiltersComponent queryRef={queryRef} />
      )}
    </>
  );
};

export default SavedFilters;
