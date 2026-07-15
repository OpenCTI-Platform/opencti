import React, { Suspense, SyntheticEvent, useCallback, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useQueryLoadingWithLoadQuery } from 'src/utils/hooks/useQueryLoading';
import SavedFiltersAutocomplete from 'src/components/saved_filters/SavedFiltersAutocomplete';
import { type SavedFiltersAutocompleteOptionType, type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { type WidgetSavedFiltersSelectionQuery } from './__generated__/WidgetSavedFiltersSelectionQuery.graphql';
import useBuildSavedFiltersOptions from 'src/components/saved_filters/useBuildSavedFiltersOptions';
import type { AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';

const widgetSavedFiltersSelectionQuery = graphql`
  query WidgetSavedFiltersSelectionQuery($filters: FilterGroup) {
    savedFilters(first: 100, filters: $filters) {
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

interface WidgetSavedFiltersComponentProps {
  queryRef: PreloadedQuery<WidgetSavedFiltersSelectionQuery>;
  onSelect: (savedFilterId: string) => void;
  onClear: () => void;
  selectedFilterId?: string | null;
  onRefetch: () => void;
}

const WidgetSavedFiltersComponent = ({
  queryRef,
  onSelect,
  onClear,
  selectedFilterId,
  onRefetch,
}: WidgetSavedFiltersComponentProps) => {
  const { savedFilters } = usePreloadedQuery(widgetSavedFiltersSelectionQuery, queryRef);
  const data = savedFilters?.edges?.map(({ node }) => node) ?? [];

  const options = useBuildSavedFiltersOptions(data);

  const selectedOption = selectedFilterId
    ? options.find((o) => o.value.id === selectedFilterId)
    : undefined;

  const [inputValue, setInputValue] = useState(selectedOption?.label ?? '');

  const handleChange = (option: SavedFiltersAutocompleteOptionType) => {
    onSelect(option.value.id);
    setInputValue(option.label);
  };

  const handleDelete = (deleted: SavedFiltersSelectionData) => {
    if (selectedFilterId === deleted.id) {
      onClear();
      setInputValue('');
    }
    onRefetch();
  };

  const handleInputChange = (_: SyntheticEvent, value: string, reason: AutocompleteInputChangeReason) => {
    if (reason === 'input') setInputValue(value);
  };

  return (
    <SavedFiltersAutocomplete
      isDisabled={!data.length}
      value={selectedOption}
      inputValue={inputValue}
      onChange={handleChange}
      onInputChange={handleInputChange}
      onDelete={handleDelete}
      options={options}
      onRefetch={onRefetch}
    />
  );
};

interface WidgetSavedFiltersSelectionProps {
  scope: string;
  onSelect: (savedFilterId: string) => void;
  onClear: () => void;
  selectedFilterId?: string | null;
}

/**
 * Standalone saved filters dropdown for widget configuration.
 * Does not depend on DataTableContext.
 */
const WidgetSavedFiltersSelection = ({
  scope,
  onSelect,
  onClear,
  selectedFilterId,
}: WidgetSavedFiltersSelectionProps) => {
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<WidgetSavedFiltersSelectionQuery>(
    widgetSavedFiltersSelectionQuery,
    {},
  );

  const handleRefetch = useCallback(() => {
    loadQuery({}, { fetchPolicy: 'network-only' });
  }, [loadQuery, scope]);

  return (
    <>
      {queryRef
        && (
          <Suspense fallback={<SavedFiltersAutocomplete isDisabled />}>
            <WidgetSavedFiltersComponent
              queryRef={queryRef}
              onSelect={onSelect}
              onClear={onClear}
              selectedFilterId={selectedFilterId}
              onRefetch={handleRefetch}
            />
          </Suspense>
        )
      }
    </>
  );
};

export default WidgetSavedFiltersSelection;
