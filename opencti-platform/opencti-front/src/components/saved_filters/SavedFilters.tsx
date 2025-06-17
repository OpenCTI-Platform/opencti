import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { SavedFiltersQuery, SavedFiltersQuery$variables } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import getSavedFilterScopeFilter from './getSavedFilterScopeFilter';
import SavedFilterSelection, { type SavedFiltersSelectionData } from './SavedFilterSelection';
import SavedFiltersAutocomplete from './SavedFiltersAutocomplete';

const savedFiltersQuery = graphql`
  query SavedFiltersQuery($filters: FilterGroup) {
    savedFilters(first: 100, filters: $filters) @connection(key: "SavedFilters_savedFilters") {
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
  currentSavedFilter?: SavedFiltersSelectionData;
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
};

const SavedFiltersComponent = ({ queryRef, currentSavedFilter, setCurrentSavedFilter }: SavedFiltersComponentProps) => {
  const { savedFilters } = usePreloadedQuery(savedFiltersQuery, queryRef);

  return (
    <SavedFilterSelection
      isDisabled={!savedFilters?.edges?.length}
      data={savedFilters?.edges?.map(({ node }) => node) ?? []}
      currentSavedFilter={currentSavedFilter}
      setCurrentSavedFilter={setCurrentSavedFilter}
    />
  );
};

type SavedFiltersProps = {
  currentSavedFilter?: SavedFiltersSelectionData;
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
};

const SavedFilters = ({ currentSavedFilter, setCurrentSavedFilter }: SavedFiltersProps) => {
  const {
    useDataTablePaginationLocalStorage: {
      localStorageKey,
    },
  } = useDataTableContext();

  const filters = getSavedFilterScopeFilter(localStorageKey);
  const queryOptions = { filters } as unknown as SavedFiltersQuery$variables;

  const queryRef = useQueryLoading<SavedFiltersQuery>(savedFiltersQuery, queryOptions);

  const isRestrictedStorageKey = localStorageKey.includes('_stixCoreRelationshipCreationFromEntity');
  if (isRestrictedStorageKey) return null;

  return (
    <>
      {queryRef
        ? (
          <Suspense fallback={<SavedFiltersAutocomplete isDisabled/>}>
            <SavedFiltersComponent
              queryRef={queryRef}
              currentSavedFilter={currentSavedFilter}
              setCurrentSavedFilter={setCurrentSavedFilter}
            />
          </Suspense>
        )
        : <SavedFiltersAutocomplete isDisabled />
      }
    </>
  );
};

export default SavedFilters;
