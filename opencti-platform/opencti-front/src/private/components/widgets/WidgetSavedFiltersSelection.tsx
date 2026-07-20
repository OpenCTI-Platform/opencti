import React, { Suspense, SyntheticEvent, useCallback, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useQueryLoadingWithLoadQuery } from 'src/utils/hooks/useQueryLoading';
import SavedFiltersAutocomplete from 'src/components/saved_filters/SavedFiltersAutocomplete';
import { type SavedFiltersAutocompleteOptionType } from 'src/components/saved_filters/SavedFilterSelection';
import { type WidgetSavedFiltersSelectionQuery } from './__generated__/WidgetSavedFiltersSelectionQuery.graphql';
import useBuildSavedFiltersOptions from 'src/components/saved_filters/useBuildSavedFiltersOptions';
import type { AutocompleteInputChangeReason } from '@mui/material/useAutocomplete/useAutocomplete';
import ClearFiltersIcon from 'src/components/filters/ClearFiltersIcon';
import WidgetCustomFiltersIcon from 'src/components/saved_filters/WidgetCustomFiltersIcon';
import Divider from "@mui/material/Divider";

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
  onDeselect: () => void;
  onClear: () => void;
  selectedFilterId?: string | null;
  onRefetch: () => void;
}

const WidgetSavedFiltersComponent = ({
  queryRef,
  onSelect,
  onDeselect,
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

  const handleClear = () => {
    onClear();
    setInputValue('');
  };

  const handleInputChange = (_: SyntheticEvent, value: string, reason: AutocompleteInputChangeReason) => {
    if (reason === 'input') setInputValue(value);
  };

  return (
    <>
      <SavedFiltersAutocomplete
        isDisabled={!data.length}
        value={selectedOption}
        inputValue={inputValue}
        onChange={handleChange}
        onInputChange={handleInputChange}
        options={options}
        onRefetch={onRefetch}
      />
      <ClearFiltersIcon
        disabled={!selectedFilterId}
        onClear={handleClear}
      />
      <Divider orientation="vertical" flexItem />
      <WidgetCustomFiltersIcon onClick={onDeselect} />
    </>
  );
};

interface WidgetSavedFiltersSelectionProps {
  scope: string;
  onSelect: (savedFilterId: string) => void;
  onDeselect: () => void;
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
  onDeselect,
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
              onDeselect={onDeselect}
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
