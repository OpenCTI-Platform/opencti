import React, { Suspense, useCallback } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useQueryLoadingWithLoadQuery } from 'src/utils/hooks/useQueryLoading';
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
          creator_id
          currentUserAccessRight
          authorizedMembers {
            id
            name
            entity_type
            access_right
            member_id
          }
        }
      }
    }
  }
`;

type SavedFiltersComponentProps = {
  queryRef: PreloadedQuery<SavedFiltersQuery>;
  currentSavedFilter?: SavedFiltersSelectionData;
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
  onRefetch: () => void;
};

const SavedFiltersComponent = ({ queryRef, currentSavedFilter, setCurrentSavedFilter, onRefetch }: SavedFiltersComponentProps) => {
  const { savedFilters } = usePreloadedQuery(savedFiltersQuery, queryRef);

  return (
    <SavedFilterSelection
      isDisabled={!savedFilters?.edges?.length}
      data={savedFilters?.edges?.map(({ node }) => node) ?? []}
      currentSavedFilter={currentSavedFilter}
      setCurrentSavedFilter={setCurrentSavedFilter}
      onRefetch={onRefetch}
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

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<SavedFiltersQuery>(savedFiltersQuery, queryOptions);

  const handleRefetch = useCallback(() => {
    loadQuery(queryOptions, { fetchPolicy: 'network-only' });
  }, [loadQuery, localStorageKey]);

  const isRestrictedStorageKey = localStorageKey.includes('_stixCoreRelationshipCreationFromEntity');
  if (isRestrictedStorageKey) return null;

  return (
    <>
      {queryRef
        ? (
            <Suspense fallback={<SavedFiltersAutocomplete isDisabled />}>
              <SavedFiltersComponent
                queryRef={queryRef}
                currentSavedFilter={currentSavedFilter}
                setCurrentSavedFilter={setCurrentSavedFilter}
                onRefetch={handleRefetch}
              />
            </Suspense>
          )
        : <SavedFiltersAutocomplete isDisabled />
      }
    </>
  );
};

export default SavedFilters;
