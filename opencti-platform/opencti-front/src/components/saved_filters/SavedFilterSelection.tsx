import React, { useState, useEffect } from 'react';
import SavedFilterDeleteDialog from 'src/components/saved_filters/SavedFilterDeleteDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { SavedFiltersQuery$data } from 'src/components/saved_filters/__generated__/SavedFiltersQuery.graphql';
import SavedFiltersAutocomplete from 'src/components/saved_filters/SavedFiltersAutocomplete';

export type SavedFiltersSelectionData = NonNullable<NonNullable<SavedFiltersQuery$data['savedFilters']>['edges']>[0]['node'];

type SavedFilterSelectionProps = {
  isDisabled: boolean;
  data: SavedFiltersSelectionData[];
};

export type AutocompleteOptionType = {
  label: string;
  value: SavedFiltersSelectionData;
};

const SavedFilterSelection = ({ isDisabled, data }: SavedFilterSelectionProps) => {
  const {
    useDataTablePaginationLocalStorage: {
      helpers,
      viewStorage: { filters },
    },
  } = useDataTableContext();

  const [selectedSavedFilter, setSelectedSavedFilter] = useState<AutocompleteOptionType>();
  const [inputValue, setInputValue] = useState<string>('');
  const [savedFilterToDelete, setSavedFilterToDelete] = useState<string>();

  const options = data.map((item) => ({
    label: item.name,
    value: item,
  }));

  const handleResetInput = () => {
    setSelectedSavedFilter(undefined);
    setInputValue('');
  };

  useEffect(() => {
    if (isDisabled && !!selectedSavedFilter) {
      handleResetInput();
    }
  }, [isDisabled]);

  useEffect(() => {
    if (!filters?.filters.length && !filters?.filterGroups.length) {
      handleResetInput();
    }
  }, [filters]);

  const handleSelect = (selectionOption: AutocompleteOptionType) => {
    setSelectedSavedFilter(selectionOption);
    setInputValue(selectionOption.label);
    helpers.handleSetFilters(JSON.parse(selectionOption.value.filters));
  };

  const resetSavedFilterToDelete = () => setSavedFilterToDelete(undefined);

  const handleDelete = (option: SavedFiltersSelectionData) => setSavedFilterToDelete(option.id);

  return (
    <>
      <SavedFiltersAutocomplete
        isDisabled={isDisabled}
        options={options}
        onDelete={handleDelete}
        onSelect={handleSelect}
        value={selectedSavedFilter}
        inputValue={inputValue}
      />
      {!!savedFilterToDelete && (
        <SavedFilterDeleteDialog savedFilterToDelete={savedFilterToDelete} onClose={resetSavedFilterToDelete} onReset={handleResetInput} />
      )}
    </>
  );
};
export default SavedFilterSelection;
